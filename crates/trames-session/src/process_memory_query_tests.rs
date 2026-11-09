// SPDX-License-Identifier: GPL-3.0-or-later
use super::tests::{kernel, process};
use super::*;
use trames_memory::{Permissions, PAGE_SIZE};

#[test]
fn memory_observations_keep_shared_mm_cohorts_without_mapping_checkpoints() {
    for (cpus, slots) in [(4, 4), (12, 12), (4, 1)] {
        for (number, args, expected) in [
            (236u32, [0x1000, 0, 0, 0x20001, 3, 0], 0u64),
            (236, [0x1000, 0x1010, 65, 0, 4, 0], 0),
            (236, [0x1000, 0, 0, 0x30000, 2, 0], error(Errno(14))),
            (232, [0x10000, 3 * PAGE_SIZE, 0x1000, 0, 0, 0], 0),
            (232, [0x20000, 2 * PAGE_SIZE, 0x1000, 0, 0, 0], 0),
            (232, [0x30000, PAGE_SIZE, 0x1000, 0, 0, 0], error(Errno(12))),
            (233, [0x20000, 2 * PAGE_SIZE, 3, 0, 0, 0], 0),
            (233, [0x20000, 2 * PAGE_SIZE, 14, 0, 0, 0], 0),
            (233, [0x30000, PAGE_SIZE, 0, 0, 0, 0], error(Errno(12))),
        ] {
            let mut k = kernel();
            k.cpu_count = cpus;
            k.workers = crate::workers::Pool::new(slots);
            k.per_cpu = vec![Duration::ZERO; cpus];
            k.profile_syscalls = true;
            let mut memory = Memory::default();
            memory.map(0x1000, 8 * PAGE_SIZE, Permissions::RW).unwrap();
            memory.map(0x10000, 3 * PAGE_SIZE, Permissions::RW).unwrap();
            memory.reserve(0x20000, 2 * PAGE_SIZE, false).unwrap();
            memory.write(0x1000, &[0xa5; 4096]).unwrap();
            memory.write(0x11000, &[42]).unwrap();
            // Each actor observes once and parks on an original infinite
            // futex wait. Idle completion proves every task ran without relying
            // on a host-time/global-budget fairness assumption.
            let words = [
                0xaa1403e0u32,
                0xaa1503e1,
                0xaa1603e2,
                0xaa1703e3,
                0xaa1803e4,
                0xaa1903e5,
                0xd4000001,
                0xaa0003f3,
                0xd2840000,
                0xd2801001,
                0xd2800002,
                0xd2800003,
                0xd2800c48,
                0xd4000001,
                0x14000000,
            ];
            memory
                .write(
                    0x4000,
                    &words
                        .into_iter()
                        .flat_map(u32::to_le_bytes)
                        .collect::<Vec<_>>(),
                )
                .unwrap();
            memory.protect(0x4000, PAGE_SIZE, Permissions::RX).unwrap();
            let used = memory.resident_bytes();
            for id in 1..=cpus {
                let mut p = process();
                p.tgid = id as u32;
                p.vm_id = 1;
                p.memory = memory.share();
                p.signals.io.scheduling.set_affinity((1 << slots) - 1);
                let mut args = args;
                // Every original task has its own result buffer in this mm.
                if number == 232 {
                    args[2] += id as u64 * 128;
                } else if number == 236 {
                    args[0] += id as u64 * 128;
                    if args[1] != 0 {
                        args[1] += id as u64 * 128;
                    }
                }
                for (i, value) in args.into_iter().enumerate() {
                    p.cpu.set_x(20 + i, value);
                }
                p.cpu.set_x(8, number as u64);
                k.processes.insert(id as u32, p);
            }
            drop(memory);
            assert!(k
                .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
                .unwrap());
            assert!(k.worker_syscalls > 0);
            assert_eq!(k.worker_syscalls, k.syscalls);
            assert_eq!(k.parallel_rounds, 1);
            assert_eq!(
                k.vm_checkpoint_groups, 0,
                "number={number} cpus={cpus} slots={slots}"
            );
            assert!(
                k.cohort_return_syscalls.is_empty(),
                "{:?}",
                k.cohort_return_syscalls
            );
            assert_eq!(k.service_requests, 0);
            for (id, p) in k.processes.iter() {
                assert_eq!(p.cpu.x(19), expected, "pid={id} number={number}");
                assert_eq!(
                    p.memory.resident_bytes(),
                    used,
                    "observation cannot allocate target bytes"
                );
                if number == 232 && expected == 0 {
                    let at = 0x1000 + id as u64 * 128;
                    let length = if args[0] == 0x10000 { 3 } else { 2 };
                    let expected = if length == 3 {
                        vec![0, 1, 0]
                    } else {
                        vec![0, 0]
                    };
                    let mut bytes = vec![0; length];
                    p.memory.read(at, &mut bytes).unwrap();
                    assert_eq!(bytes, expected);
                }
            }
        }
    }
}
