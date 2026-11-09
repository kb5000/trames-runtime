// SPDX-License-Identifier: GPL-3.0-or-later
use super::tests::{kernel, process};
use super::*;
use trames_memory::{Permissions, PAGE_SIZE};

fn mov(code: &mut Vec<u32>, register: u32, value: u64) {
    code.push(0xd2800000 | ((value as u16 as u32) << 5) | register);
    for shift in 1..4 {
        let word = ((value >> (shift * 16)) & 0xffff) as u32;
        if word != 0 {
            code.push(0xf2800000 | (shift << 21) | (word << 5) | register);
        }
    }
}

#[test]
fn final_dispatch_family_and_canonical_errors_complete_on_source() {
    for (cpus, slots, filtered) in [(4, 4, false), (12, 12, false), (4, 1, false), (4, 1, true)] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; cpus];
        k.profile_syscalls = true;
        let mut root = process();
        root.linux
            .vfs
            .import_file(b"/file", b"unchanged".to_vec())
            .unwrap();
        assert_eq!(root.linux.vfs.open_at(-100, b"/file", 2, 0).unwrap(), 3);
        assert_eq!(
            root.linux
                .vfs
                .open_at(-100, b"/file", trames_vfs::O_PATH, 0)
                .unwrap(),
            4
        );
        assert_eq!(root.linux.vfs.open_at(-100, b"/", 0, 0).unwrap(), 5);
        assert_eq!(root.linux.vfs.pipe(0).unwrap(), [6, 7]);
        assert_eq!(root.linux.vfs.dup(3, 0, false).unwrap(), 8);
        root.linux.vfs.seek(3, 3, 0).unwrap();
        if filtered {
            root.memory
                .write_array(0x1300, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0x14, 0, 0, 0, 0, 0, 0])
                .unwrap();
            root.memory
                .write_array(0x1400, [6, 0, 0, 0, 0, 0, 0xff, 0x7f])
                .unwrap();
            root.linux.vfs.credentials.caps.no_new_privs.set();
            assert_eq!(k.seccomp(&mut root, [1, 0, 0x1300, 0, 0, 0]), Ok(0));
        }
        let mut calls = Vec::new();
        for number in [
            22, 28, 31, 46, 47, 67, 68, 69, 70, 71, 76, 82, 83, 86, 87, 92, 98, 267, 285, 286, 287,
            425, 441,
        ] {
            let args = [u64::MAX; 6];
            for (register, value) in args.iter().enumerate() {
                root.cpu.set_x(register, *value);
            }
            root.cpu.set_x(8, number as u64);
            let canonical = k.syscall(
                1,
                &mut root,
                number,
                args,
                &mut trames_linux::CapturedOutput::default(),
            );
            let expected = canonical
                .unwrap_or_else(|e| Some(0u64.wrapping_sub(e.0 as u64)))
                .expect("canonical terminal result");
            calls.push((number as u64, args, expected as i64));
        }
        calls.extend([
            (20, [0; 6], 9),
            (20, [0; 6], 10),
            (19, [1, 0, 0, 0, 0, 0], 11),
            (21, [9, 1, 11, 0x1700, 0, 0], 0),
            (21, [10, 1, 9, 0x1700, 0, 0], 0),
            (22, [10, 0x1800, 1, 0, 0, 0], 1),
            (21, [3, 2, 11, 0, 0, 0], -22),
            (21, [10, 2, u32::MAX as u64, 0, 0, 0], -9),
            (21, [10, 2, 9, 0, 0, 0], 0),
            (31, [1, 0, 0, 0, 0, 0], 0),
            (31, [3, 0, 0, 0, 0, 0], -95),
            (92, [0; 6], 0),
            (92, [1, 0, 0, 0, 0, 0], -22),
            (98, [0x1000, 2, 0, 0, 0, 0], -38),
            (67, [u32::MAX as u64, 0x1000, 1, 0, 0, 0], -9),
            (82, [u32::MAX as u64, 0, 0, 0, 0, 0], -9),
            (287, [u32::MAX as u64, 0, 0, 0, 0, 1], -95),
            (47, [u32::MAX as u64, 0, i64::MAX as u64, 1, 0, 0], -27),
            (57, [3, 0, 0, 0, 0, 0], 0),
            (24, [5, 3, 0, 0, 0, 0], 3),
            (67, [3, 0x1000, 1, 0, 0, 0], -21),
            (57, [3, 0, 0, 0, 0, 0], 0),
            (24, [8, 3, 0, 0, 0, 0], 3),
            (67, [3, 0x1000, 1, 0, 0, 0], 1),
        ]);
        root.memory
            .write_array(0x1700, [1, 0, 0, 0, 0, 0, 0, 0, 77, 0, 0, 0, 0, 0, 0, 0])
            .unwrap();
        let mut code = Vec::new();
        mov(&mut code, 24, 0x1900);
        for (i, (number, args, _)) in calls.iter().enumerate() {
            for (register, value) in args.iter().enumerate() {
                mov(&mut code, register as u32, *value);
            }
            mov(&mut code, 8, *number);
            code.extend([0xd4000001, 0xf9000300 | ((i as u32) << 10)]);
        }
        code.extend([0xd2850000, 0xd2800021, 0xb9000001]);
        let wait = [
            0xd2860000, 0xd2801001, 0xd2800002, 0xd2800003, 0xd2800c48, 0xd4000001, 0x14000000,
        ];
        code.extend(wait);
        root.memory
            .write(
                0x4000,
                &code
                    .iter()
                    .flat_map(|w| w.to_le_bytes())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        root.memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        let mut peer = root.fork();
        peer.vm_id = 2;
        peer.tgid = 2;
        for (pid, p) in [(1, root), (2, peer)] {
            k.processes.insert(pid, p);
        }
        assert!(k
            .parallel_round(&mut trames_linux::CapturedOutput::default(), 1_000_000)
            .unwrap());
        eprintln!("final-dispatch CPUs={cpus} slots={slots} filter={filtered} cohorts={} returned={:?} scopes={}", k.parallel_rounds, k.cohort_return_syscalls, k.vm_checkpoint_groups);
        for pid in [1, 2] {
            let mut p = k.processes.get_mut(&pid).unwrap();
            assert_eq!(
                p.memory.read_array::<4>(0x2800).unwrap(),
                1u32.to_le_bytes(),
                "pid {pid}"
            );
            for (i, (number, args, expected)) in calls.iter().enumerate() {
                assert_eq!(
                    p.memory.read_u64(0x1900 + i as u64 * 8).unwrap(),
                    *expected as u64,
                    "pid {pid} call {i} number={number} args={args:?}"
                );
            }
            assert_eq!(p.linux.vfs.seek(3, 0, 1), Ok(3));
            assert_eq!(p.linux.vfs.pread(3, 9, 0).unwrap(), b"unchanged");
        }
        assert_eq!(k.parallel_rounds, 1);
        assert!(k.cohort_return_syscalls.is_empty());
        assert_eq!(k.service_requests, 0);
        assert_eq!(k.vm_checkpoint_groups, 0);
    }
}
