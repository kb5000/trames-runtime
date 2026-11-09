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
fn guest_msync_shared_aliases_private_and_unrelated_mms_complete_on_source() {
    for (cpus, slots, filtered) in [(4, 4, false), (12, 12, false), (4, 1, false), (4, 1, true)] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; cpus];
        k.profile_syscalls = true;
        let mut root = process();
        root.linux
            .vfs
            .import_file(b"/sync", vec![7; 2 * PAGE_SIZE as usize])
            .unwrap();
        let fd = root.linux.vfs.open_at(-100, b"/sync", 2, 0).unwrap();
        assert_eq!(fd, 3);
        for (address, shared) in [(0x10000, true), (0x20000, false)] {
            root.memory
                .map_backed(
                    address,
                    root.linux
                        .vfs
                        .mapping_pages(fd, 0, 2 * PAGE_SIZE, shared, true)
                        .unwrap(),
                    shared,
                    Permissions::RW,
                    false,
                )
                .unwrap();
        }
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
        let cases: [([u64; 6], i64); 11] = [
            ([0x10001, 0, 0, 0, 0, 0], -22),
            ([0x10000, 1, 5, 0, 0, 0], -22),
            ([0x10000, 3 * PAGE_SIZE, 4, 0, 0, 0], -12),
            ([0x10000, 0, 8, 0, 0, 0], -22),
            ([0x900000, 0, 0, 0, 0, 0], 0),
            ([0x1000, PAGE_SIZE, 4, 0, 0, 0], 0),
            ([0x20000, 2 * PAGE_SIZE, 4, 0, 0, 0], 0),
            ([0x10000, 2 * PAGE_SIZE, 4, 0, 0, 0], 0),
            ([0x10000, 2 * PAGE_SIZE, 2, 0, 0, 0], 0),
            ([0x10000, 2 * PAGE_SIZE, 1, 0, 0, 0], 0),
            ([0x10000, 2 * PAGE_SIZE, 0, 0, 0, 0], 0),
        ];
        let mut code = Vec::new();
        mov(&mut code, 24, 0x1900);
        mov(&mut code, 9, 0x41424344);
        mov(&mut code, 10, 0x10000);
        code.push(0xb9000149);
        for (i, (args, _)) in cases.iter().enumerate() {
            for (register, value) in args.iter().enumerate() {
                mov(&mut code, register as u32, *value);
            }
            mov(&mut code, 8, 227);
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
        let mut alias = root.fork();
        alias.vm_id = 2;
        alias.tgid = 2;
        let mut independent = process();
        independent.vm_id = 3;
        independent.tgid = 3;
        let mut peer_code = vec![0xd2850000u32, 0xd2800021, 0xb9000001];
        peer_code.extend(wait);
        independent
            .memory
            .write(
                0x4000,
                &peer_code
                    .iter()
                    .flat_map(|w| w.to_le_bytes())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        independent
            .memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        for (pid, p) in [(1, root), (2, alias), (3, independent)] {
            k.processes.insert(pid, p);
        }
        assert!(k
            .parallel_round(&mut trames_linux::CapturedOutput::default(), 1_000_000)
            .unwrap());
        eprintln!(
            "msync CPUs={cpus} slots={slots} filter={filtered} cohorts={} returned={:?} scopes={}",
            k.parallel_rounds, k.cohort_return_syscalls, k.vm_checkpoint_groups
        );
        for pid in [1, 2, 3] {
            let p = k.processes.get_mut(&pid).unwrap();
            assert_eq!(
                p.memory.read_array::<4>(0x2800).unwrap(),
                1u32.to_le_bytes(),
                "pid {pid}"
            );
            if pid != 3 {
                for (i, (_, expected)) in cases.iter().enumerate() {
                    assert_eq!(
                        p.memory.read_u64(0x1900 + i as u64 * 8).unwrap(),
                        *expected as u64,
                        "pid {pid} call {i}"
                    );
                }
                assert_eq!(p.memory.read_array::<4>(0x10000).unwrap(), *b"DCBA");
                assert_eq!(p.memory.read_array::<4>(0x20000).unwrap(), *b"DCBA");
                assert_eq!(p.linux.vfs.pread(3, 4, 0).unwrap(), b"DCBA");
            }
        }
        assert_eq!(k.parallel_rounds, 1);
        assert!(k.cohort_return_syscalls.is_empty());
        assert_eq!(k.service_requests, 0);
    }
}
