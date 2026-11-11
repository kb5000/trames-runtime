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
fn guest_memfd_creation_sparse_mapping_seals_aliases_and_reuse_stay_on_source() {
    for (cpus, slots, filtered) in [(4, 4, false), (12, 12, false), (4, 1, false), (4, 1, true)] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; cpus];
        k.profile_syscalls = true;
        let mut root = process();
        let nodes = root.linux.vfs.capacity().nodes_used;
        root.memory.write(0x1600, b"guest-memory\0").unwrap();
        root.memory.write(0x1640, b"replacement\0").unwrap();
        root.memory.write(0x1700, b"payload").unwrap();
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
        let calls: [(u64, [u64; 6], i64); 24] = [
            (279, [0x1600, 4, 0, 0, 0, 0], -22),
            (279, [0x9000, 0, 0, 0, 0, 0], -14),
            (279, [0x1600, 3, 0, 0, 0, 0], 3),
            (46, [3, 1 << 30, 0, 0, 0, 0], 0),
            (64, [3, 0x1700, 7, 0, 0, 0], 7),
            (67, [3, 0x1800, 7, 0, 0, 0], 7),
            (25, [3, 1033, 6, 0, 0, 0], 0),
            (25, [3, 1034, 0, 0, 0, 0], 6),
            (222, [0x10000, 4096, 3, 0x11, 3, 0], 0x10000),
            // The raw guest store is emitted immediately after mmap.
            (215, [0x10000, 4096, 0, 0, 0, 0], 0),
            (25, [3, 1033, 8, 0, 0, 0], 0),
            (25, [3, 1034, 0, 0, 0, 0], 14),
            (25, [3, 1033, 1, 0, 0, 0], 0),
            (25, [3, 1034, 0, 0, 0, 0], 15),
            (23, [3, 0, 0, 0, 0, 0], 4),
            (57, [3, 0, 0, 0, 0, 0], 0),
            (279, [0x1640, 0, 0, 0, 0, 0], 3),
            (68, [4, 0x1700, 1, 0, 0, 0], -1),
            (62, [4, 0, 0, 0, 0, 0], 0),
            (63, [4, 0x1800, 7, 0, 0, 0], 7),
            (64, [3, 0x1700, 1, 0, 0, 0], 1),
            (25, [4, 1034, 0, 0, 0, 0], 15),
            (25, [3, 1034, 0, 0, 0, 0], 1),
            (57, [4, 0, 0, 0, 0, 0], 0),
        ];
        let mut code = Vec::new();
        mov(&mut code, 24, 0x1900);
        for (i, (number, args, _)) in calls.iter().enumerate() {
            for (register, value) in args.iter().enumerate() {
                mov(&mut code, register as u32, *value);
            }
            mov(&mut code, 8, *number);
            code.extend([0xd4000001, 0xf9000300 | ((i as u32) << 10)]);
            if *number == 222 {
                mov(&mut code, 9, 0x41424344);
                mov(&mut code, 10, 0x10000);
                code.push(0xb9000149);
            }
        }
        code.extend([0xd2850000, 0xd2800021, 0xb9000001]);
        let wait = [
            0xd2860000, 0xd2801001, 0xd2800002, 0xd2800003, 0xd2800c48, 0xd4000001, 0x14000000,
        ];
        code.extend(wait);
        let mut peer_code = vec![0xd2850000, 0xd2800021, 0xb9000001];
        peer_code.extend(wait);
        for (at, words) in [(0x4000, code.as_slice()), (0x6000, peer_code.as_slice())] {
            root.memory
                .write(
                    at,
                    &words
                        .iter()
                        .flat_map(|w| w.to_le_bytes())
                        .collect::<Vec<_>>(),
                )
                .unwrap();
            root.memory.protect(at, PAGE_SIZE, Permissions::RX).unwrap();
        }
        let mut peer = root.fork();
        peer.vm_id = 2;
        peer.tgid = 2;
        peer.cpu.set_pc(0x6000);
        k.processes.insert(1, root);
        k.processes.insert(2, peer);
        // Complete the accepted cohort up to its actual futex idle state.
        // A bounded 10 ms round can return before the stores under host load;
        // that host scheduling cutoff is not the behavior this fixture checks.
        assert!(k
            .parallel_epoch(
                &mut trames_linux::CapturedOutput::default(),
                1_000_000,
                true
            )
            .unwrap());
        eprintln!(
            "memfd CPUs={cpus} slots={slots} filter={filtered} cohorts={} returned={:?} scopes={}",
            k.parallel_rounds, k.cohort_return_syscalls, k.vm_checkpoint_groups
        );
        for pid in [1, 2] {
            assert_eq!(
                k.processes
                    .get_mut(&pid)
                    .unwrap()
                    .memory
                    .read_array::<4>(0x2800)
                    .unwrap(),
                1u32.to_le_bytes(),
                "pid={pid}, pc={:#x}, instructions={}",
                k.processes.read(&pid).cpu.pc,
                k.instructions,
            );
        }
        let root = k.processes.get_mut(&1).unwrap();
        for (i, (number, args, expected)) in calls.iter().enumerate() {
            assert_eq!(
                root.memory.read_u64(0x1900 + i as u64 * 8).unwrap(),
                *expected as u64,
                "call {i} number={number} args={args:?}"
            );
        }
        assert_eq!(root.memory.read_array::<7>(0x1800).unwrap(), *b"DCBAoad");
        assert_eq!(root.linux.vfs.capacity().nodes_used, nodes + 1);
        assert_eq!(k.parallel_rounds, 1);
        assert!(k.cohort_return_syscalls.is_empty());
        assert_eq!(k.service_requests, 0);
    }
}
