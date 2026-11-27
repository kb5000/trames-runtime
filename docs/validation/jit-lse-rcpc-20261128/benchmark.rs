// SPDX-License-Identifier: GPL-3.0-or-later
//! Matched finite ARM64 payloads. Reports CPU backend/worker boundaries, not
//! shared Linux syscall handlers or a bare-metal/native instruction baseline.
use serde_json::{json, Value};
use std::{hint::black_box, time::Instant};
use trames_engine::{Cpu as Backend, SliceOutcome};
use trames_memory::{parallel::Registry, CpuMemory, Memory, Permissions, PAGE_SIZE};

const CODE: u64 = 0x1000;
const DATA: u64 = 0x2000;
const BUDGET: u64 = 1_048_576;
const SAMPLES: usize = 5;

trait Bench: Backend {
    fn diagnostics(engine: &Self::Engine) -> Value;
}
impl Bench for trames_interpreter::Cpu {
    fn diagnostics(_: &Self::Engine) -> Value {
        json!({})
    }
}
impl Bench for trames_jit::Cpu {
    fn diagnostics(engine: &Self::Engine) -> Value {
        let memory = engine.memory_stats();
        json!({"fallback_instructions":engine.stats.fallback_instructions,
            "native_instructions":engine.stats.native_instructions,
            "direct_syscall_exits":engine.stats.direct_syscall_exits,
            "memory_instructions":memory.instructions,"staged":memory.staged,
            "direct":memory.direct,"address_reuses":engine.compilation_stats().address_reuses,"hardware":memory.hardware,"fused_entries":memory.fused_entries,"fused_blocks":memory.fused_blocks})
    }
}

struct Work {
    name: &'static str,
    words: Vec<u32>,
    trips: u64,
    iterations: u64,
    per_trip_instructions: u64,
    delta: u64,
    memory: bool,
    looping_svc: bool,
}
fn branch_to_start(index: usize) -> u32 {
    0x14000000 | ((-(index as i32)) as u32 & 0x03ffffff)
}
fn workloads(quick: bool) -> Vec<Work> {
    let mut integer = vec![0x91000400; 31];
    integer.extend_from_slice(&[0xf1000442, 0x54fffc01, 0xd4000001]);
    let mut result = vec![Work {
        name: "integer-loop",
        words: integer,
        trips: 1,
        iterations: if quick { 16 } else { 262144 },
        per_trip_instructions: 33,
        delta: 31,
        memory: false,
        looping_svc: false,
    }];
    for (name, iterations) in [
        ("memory-64k", if quick { 16 } else { 65536 }),
        ("memory-1m", if quick { 64 } else { 1_048_576 }),
    ] {
        result.push(Work {
            name,
            words: vec![
                0xf9400020, 0x91000400, 0xf9000020, 0xf1000442, 0x54ffff81, 0xd4000001,
            ],
            trips: 1,
            iterations,
            per_trip_instructions: 5,
            delta: 1,
            memory: true,
            looping_svc: false,
        });
    }
    result.push(Work {
        name: "memory-stream-512k",
        words: vec![0xf9400020,0x91000400,0xf8008420,0xf1000442,0x54ffff81,0xd4000001],
        trips: 1, iterations: if quick {16} else {65536},
        per_trip_instructions: 5, delta: 1, memory: true, looping_svc: false,
    });
    for (name, load, store) in [
        ("pairs-1m", 0xa9401020, 0xa9001020),
        ("ordered-1m", 0xc8dffc20, 0xc89ffc20),
    ] {
        result.push(Work { name, words: vec![load,0x91000400,store,0xf1000442,0x54ffff81,0xd4000001],
            trips:1, iterations:if quick {64} else {1_048_576}, per_trip_instructions:5,
            delta:1, memory:true, looping_svc:false });
    }
    result.push(Work { name:"barrier-64k", words:vec![0xf9400020,0xd5033bbf,0x91000400,0xf9000020,0xf1000442,0x54ffff61,0xd4000001],
        trips:1, iterations:if quick {16} else {65536}, per_trip_instructions:6,delta:1,memory:true,looping_svc:false });
    for (name,words,steps) in [
        ("ldadd-1m",vec![0xf8240020,0x91000400,0xf1000442,0x54ffffa1,0xd4000001],4),
        ("cas-1m",vec![0x91000404,0xc8a07c24,0x91000400,0xf1000442,0x54ffff81,0xd4000001],5),
        ("casp-1m",vec![0xa9401424,0x91000486,0xaa0503e7,0x48247c26,0xaa0603e0,0xf1000442,0x54ffff41,0xd4000001],7),
        ("rcpc-1m",vec![0xf8bfc020,0x91000400,0xc89ffc20,0xf1000442,0x54ffff81,0xd4000001],5),
        ("rcpc-unscaled-1m",vec![0xd9400020,0x91000400,0xd9000020,0xf1000442,0x54ffff81,0xd4000001],5),
    ] {
        result.push(Work{name,words,trips:1,iterations:if quick {64} else {1_048_576},
            per_trip_instructions:steps,delta:1,memory:true,looping_svc:false});
    }
    for (name, adds) in [("svc-only", 0), ("svc-continuation", 1), ("svc-16-add", 16)] {
        let mut words = vec![0x91000400; adds];
        words.push(0xd4000001);
        words.push(branch_to_start(words.len()));
        result.push(Work {
            name,
            words,
            trips: if quick { 64 } else { 10000 },
            iterations: 1,
            per_trip_instructions: adds as u64 + 2,
            delta: adds as u64 + 1,
            memory: false,
            looping_svc: true,
        });
    }
    result
}

fn measure<C: Bench>(backend: &str, mode: &str, work: Work) -> Value {
    let mut memory = Memory::default();
    memory.map(CODE, PAGE_SIZE, Permissions::RW).unwrap();
    let streaming=work.name=="memory-stream-512k";
    let data_len=if streaming { work.iterations*8 } else { PAGE_SIZE };
    let mapped=data_len.div_ceil(PAGE_SIZE)*PAGE_SIZE;
    memory.map(DATA,mapped,Permissions::RW).unwrap();
    memory.write(DATA,&vec![0;mapped as usize]).unwrap();
    for (i, word) in work.words.iter().enumerate() {
        memory
            .write_array(CODE + i as u64 * 4, word.to_le_bytes())
            .unwrap();
    }
    memory.protect(CODE, PAGE_SIZE, Permissions::RX).unwrap();
    let mut cpu = C::new(CODE, DATA + PAGE_SIZE - 16);
    cpu.set_x(1, DATA);
    cpu.set_x(4,1);
    let mut engine = C::Engine::default();
    let mut registry = Registry::default();
    let mut view = if mode != "direct" {
        C::prepare_hardware_memory(&mut memory, &mut registry).unwrap();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        C::prepare_hardware_view(&mut view);
        if mode == "worker-private" && backend != "kvm" {
            // Sole actor and all mm roots remain here, no clone/fork/host bytes
            // or mapping access until the view is dropped after all samples.
            assert!(unsafe { trames_memory::parallel::View::try_private_epoch(&mut [&mut view]) });
        }
        Some(view)
    } else {
        None
    };
    if work.looping_svc {
        // Each iteration, including the first, executes the same backbranch.
        cpu.set_pc(CODE + (work.words.len() as u64 - 1) * 4);
    }
    let logical = if work.looping_svc {
        work.per_trip_instructions * work.trips
    } else {
        work.per_trip_instructions * work.iterations + 1
    };
    let next_pc = if work.looping_svc {
        CODE + (work.words.len() as u64 - 1) * 4
    } else {
        CODE + work.words.len() as u64 * 4
    };
    let mut samples = Vec::new();
    for sample in 0..=SAMPLES {
        if !work.looping_svc {
            cpu.set_pc(CODE);
            cpu.set_x(2, work.iterations);
            if streaming { cpu.set_x(1,DATA); }
        }
        let start = Instant::now();
        let mut calls = 0u64;
        let mut yields = 0u64;
        let mut observed = 0u64;
        C::begin_execution(&mut engine).unwrap();
        for _ in 0..work.trips {
            loop {
                calls += 1;
                let outcome = if let Some(view) = &mut view {
                    cpu.run_parallel(&mut engine, view, BUDGET)
                } else {
                    cpu.run(&mut engine, &mut memory, BUDGET)
                };
                match outcome {
                    SliceOutcome::Syscall { instructions } => {
                        observed += instructions;
                        break;
                    }
                    SliceOutcome::Yield { instructions } => {
                        observed += instructions;
                        yields += 1;
                        C::finish_execution(&mut engine);
                        C::begin_execution(&mut engine).unwrap();
                    }
                    other => panic!("{backend} {} at {:#x}: {other:?}", work.name, cpu.pc()),
                }
                assert!(yields < 1_000_000, "backend made no bounded progress");
            }
            if work.looping_svc {
                // Simulate the ordinary worker committing a syscall result.
                cpu.set_x(0, cpu.x(0).wrapping_add(1));
            }
            black_box(cpu.x(0));
        }
        C::finish_execution(&mut engine);
        let ns = start.elapsed().as_nanos();
        let expected = if streaming { sample as u64 + 1 }
            else { (sample as u64 + 1) * work.trips * work.iterations * work.delta };
        assert_eq!((cpu.x(0), cpu.pc()), (expected, next_pc));
        if !work.looping_svc {
            assert_eq!(cpu.x(2), 0);
        }
        if C::EXACT_INSTRUCTIONS {
            assert_eq!(observed, logical);
        }
        samples.push(
            json!({"warmup":sample==0,"ns":ns,"calls":calls,"yields":yields,
            "syscalls":work.trips,"observed_instructions":C::EXACT_INSTRUCTIONS.then_some(observed),
            "x0":cpu.x(0),"pc":cpu.pc()}),
        );
    }
    // Validate bytes after all timing. A host borrow between timed samples would
    // revoke KVM's data alias and force an avoidable first-access fault next time.
    let data = if let Some(view) = &view {
        view.read_u64(DATA).unwrap()
    } else {
        memory.read_u64(DATA).unwrap()
    };
    if work.name=="pairs-1m" || work.name=="casp-1m" {
        let second=if let Some(view)=&view {view.read_u64(DATA+8).unwrap()} else {memory.read_u64(DATA+8).unwrap()};
        assert_eq!(second,0);
    }
    let expected_data = if streaming { SAMPLES as u64 + 1 } else if work.memory {
        (SAMPLES as u64 + 1) * work.iterations
    } else {
        0
    };
    assert_eq!(data, expected_data);
    let mut canonical=vec![0;data_len as usize];
    if let Some(view)=&view { view.read(DATA,&mut canonical).unwrap(); }
    else { memory.read(DATA,&mut canonical).unwrap(); }
    if streaming {
        assert!(canonical.chunks_exact(8).all(|b| u64::from_le_bytes(b.try_into().unwrap())==expected_data));
        assert_eq!(cpu.x(1),DATA+work.iterations*8);
    }
    let data_checksum=canonical.iter().fold(0xcbf29ce484222325u64,|hash,b| (hash ^ *b as u64).wrapping_mul(0x100000001b3));
    let mut original = vec![0; work.words.len() * 4];
    if let Some(view) = &view {
        view.read(CODE, &mut original).unwrap();
    } else {
        memory.read(CODE, &mut original).unwrap();
    }
    assert_eq!(
        original,
        work.words
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<_>>()
    );
    drop(view);
    memory.commit_parallel().unwrap();
    assert_eq!(memory.read_u64(DATA).unwrap(), expected_data);
    let mut times = samples
        .iter()
        .skip(1)
        .map(|s| s["ns"].as_u64().unwrap())
        .collect::<Vec<_>>();
    times.sort_unstable();
    json!({"kind":"workload","backend":backend,"mode":mode,"workload":work.name,
        "words":work.words,"trips":work.trips,"iterations":work.iterations,
        "logical_guest_instructions":logical,"data_bytes":data_len,"data_checksum":data_checksum,"final_x1":cpu.x(1),"exact_instructions":C::EXACT_INSTRUCTIONS,
        "median_ns":times[SAMPLES/2],"samples":samples,"final_data":data,
        "final_x0":cpu.x(0),"final_pc":cpu.pc(),"diagnostics":C::diagnostics(&engine)})
}
fn main() {
    const {
        assert!(
            cfg!(all(target_os = "linux", target_arch = "aarch64")),
            "requires AArch64 Linux"
        );
        assert!(trames_jit::NATIVE_COMPILED);
    }
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let backend = args.first().map(String::as_str).unwrap_or("jit");
    let mode = args.get(1).map(String::as_str).unwrap_or("worker");
    let quick = args.iter().any(|a| a == "--quick");
    assert!(matches!(mode, "worker" | "worker-private" | "direct"));
    assert!(matches!(backend, "interpreter" | "jit" | "kvm"));
    for work in workloads(quick) {
        let report = match backend {
            "interpreter" => measure::<trames_interpreter::Cpu>(backend, mode, work),
            "jit" => measure::<trames_jit::Cpu>(backend, mode, work),
            _ => unreachable!(),
        };
        println!("{report}");
    }
}
