// SPDX-License-Identifier: GPL-3.0-or-later
//! Representative decode probes, not ISA conformance or instruction semantics.
//! stdin: identifier + hexadecimal opcode. Checks execution against single step.
use std::io::{self, BufRead};
use trames_interpreter::{Cpu, CpuFault, Event, SliceOutcome};
use trames_memory::{Memory, Permissions, PAGE_SIZE};
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--features") {
        println!(
            "{} {} {}",
            trames_interpreter::HWCAP,
            trames_interpreter::HWCAP2,
            trames_interpreter::FEATURE_NAMES
        );
        return;
    }
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let (id, hex) = line.split_once(' ').unwrap();
        let word = u32::from_str_radix(hex, 16).unwrap();
        let mut results = Vec::new();
        for single_step in [true, false] {
            let mut memory = Memory::default();
            memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
            memory.write(0x1000, &word.to_le_bytes()).unwrap();
            memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
            memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
            let mut cpu = Cpu::new(0x1000, 0x2800);
            for reg in 0..31 {
                cpu.set_x(reg, 0x2000);
            }
            // Main/epilogue MOPS encodings require the prologue's Option-A
            // register convention. Decode probes supply that architectural
            // entry state; full multi-stage semantics have separate tests.
            if matches!(word & 0xff200c00, 0x19000400 | 0x1d000400) {
                let set = word & 0x00c00000 == 0x00c00000;
                let stage = if set {
                    (word >> 14) & 3
                } else {
                    (word >> 22) & 3
                };
                if stage != 0 {
                    cpu.set_x(((word >> 5) & 31) as usize, 16u64.wrapping_neg());
                    cpu.set_x((word & 31) as usize, 0x2010);
                    if !set {
                        cpu.set_x(((word >> 16) & 31) as usize, 0x2010);
                    }
                }
            }
            let outcome = if single_step {
                match cpu.step(&mut memory) {
                    Ok(Event::Continue) => SliceOutcome::Yield { instructions: 1 },
                    Ok(Event::Yield) => SliceOutcome::Yield { instructions: 0 },
                    Ok(Event::Syscall) => SliceOutcome::Syscall { instructions: 1 },
                    Ok(Event::NativeCall {
                        pc,
                        module,
                        function,
                    }) => SliceOutcome::NativeCall {
                        instructions: 0,
                        pc,
                        module,
                        function,
                    },
                    Err(error) => SliceOutcome::Fault(error),
                }
            } else {
                cpu.run_slice(&mut memory, 1)
            };
            let result = match outcome {
                SliceOutcome::Fault(CpuFault::Instruction { .. }) => "unsupported",
                SliceOutcome::Fault(CpuFault::Memory { .. }) => "decoded-memory-fault",
                SliceOutcome::Fault(CpuFault::Host(error)) => {
                    panic!("unexpected interpreter host error: {error}")
                }
                SliceOutcome::Fault(CpuFault::Trap { .. }) => "decoded-exception",
                SliceOutcome::Syscall { .. } => "syscall",
                SliceOutcome::NativeCall { .. } => "native-call",
                SliceOutcome::Yield { .. } => "decoded",
            };
            results.push(result);
        }
        assert!(results.iter().all(|value| value == &results[0]), "{id}");
        println!("{id} {hex} {}", results[0]);
    }
}
