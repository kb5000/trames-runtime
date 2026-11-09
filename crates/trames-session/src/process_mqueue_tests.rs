// SPDX-License-Identifier: GPL-3.0-or-later
use super::tests::{kernel, process};
use super::*;
use trames_memory::{Permissions, PAGE_SIZE};

#[test]
fn mqueue_path_directory_and_namespace_calls_keep_the_original_cohort() {
    for (cpus, slots) in [(4, 4), (12, 12), (4, 1)] {
        let mut owner = trames_vfs::Vfs::default();
        owner.mkdir_at(-100, b"/mq", 0o755).unwrap();
        owner
            .mount(None, b"/mq", Some(b"mqueue"), 14, None)
            .unwrap();
        let dir = owner
            .open_at(-100, b"/mq", trames_vfs::O_DIRECTORY, 0)
            .unwrap() as u64;
        for (number, args, expected) in [
            (79u32, [(-100i64) as u64, 0x2000, 0x1000, 0, 0, 0], 0u64),
            (291, [dir, 0x2010, 0, 0x7ff, 0x1000, 0], 0),
            (43, [0x2000, 0x1000, 0, 0, 0, 0], 0),
            (56, [(-100i64) as u64, 0x2000, 0x200000, 0, 0, 0], u64::MAX),
            (
                56,
                [dir, 0x2010, trames_vfs::O_DIRECTORY as u64, 0, 0, 0],
                u64::MAX,
            ),
            (61, [dir, 0x1000, 256, 0, 0, 0], 48),
            (62, [dir, 0, 0, 0, 0, 0], 0),
            (44, [dir, 0x1000, 0, 0, 0, 0], 0),
            (56, [dir, 0x2020, 0x42, 0o600, 0, 0], error(Errno(1))),
            (34, [dir, 0x2020, 0o700, 0, 0, 0], error(Errno(1))),
            (48, [dir, 0x2010, 7, 0, 0, 0], 0),
            (78, [dir, 0x2010, 0x1000, 128, 0, 0], error(Errno(22))),
        ] {
            let mut k = kernel();
            k.cpu_count = cpus;
            k.workers = crate::workers::Pool::new(slots);
            k.per_cpu = vec![Duration::ZERO; cpus];
            k.profile_syscalls = true;
            let mut memory = Memory::default();
            memory.map(0x1000, 8 * PAGE_SIZE, Permissions::RW).unwrap();
            memory.write(0x2000, b"/mq\0").unwrap();
            memory.write(0x2010, b".\0").unwrap();
            memory.write(0x2020, b"new\0").unwrap();
            let words = [
                0xaa1403e0u32,
                0xaa1503e1,
                0xaa1603e2,
                0xaa1703e3,
                0xaa1803e4,
                0xaa1903e5,
                0xd4000001,
                0xaa0003f3,
                0xd2860000,
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
            for id in 1..=cpus {
                let mut p = process();
                p.tgid = id as u32;
                p.vm_id = 1;
                p.memory = memory.share();
                p.linux.vfs = owner.clone();
                p.signals.io.scheduling.set_affinity((1 << slots) - 1);
                let mut args = args;
                if number == 61 {
                    args[0] = p
                        .linux
                        .vfs
                        .open_at(-100, b"/mq", trames_vfs::O_DIRECTORY, 0)
                        .unwrap() as u64;
                    args[1] += id as u64 * 256;
                }
                // Each actor owns its output bytes even though its mm is shared.
                if number == 79 {
                    args[2] += id as u64 * 256;
                }
                if number == 291 {
                    args[4] += id as u64 * 256;
                }
                if matches!(number, 43 | 44) {
                    args[1] += id as u64 * 256;
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
            assert!(
                k.cohort_return_syscalls.is_empty(),
                "syscall={number} cpus={cpus} slots={slots}: {:?}",
                k.cohort_return_syscalls
            );
            assert_eq!(k.worker_syscalls, k.syscalls);
            assert_eq!(k.parallel_rounds, 1);
            assert_eq!(k.vm_checkpoint_groups, 0);
            assert_eq!(k.service_requests, 0);
            for (id, p) in k.processes.iter() {
                if number == 56 && args[2] & 0x40 == 0 {
                    assert!(
                        p.linux.vfs.stat_fd(p.cpu.x(19) as u32).is_ok(),
                        "pid={id} syscall={number} args={args:?} result={:#x}",
                        p.cpu.x(19)
                    );
                } else {
                    assert_eq!(p.cpu.x(19), expected, "pid={id} syscall={number}");
                }
            }
        }
    }
}
