// SPDX-License-Identifier: GPL-3.0-or-later
use super::tests::{kernel, process};
use super::*;
use trames_memory::{Permissions, PAGE_SIZE};

fn mov(code: &mut Vec<u32>, r: u32, value: u32) {
    code.push(0xd2800000 | (value << 5) | r);
}
fn words<C: Cpu>(p: &mut Process<C>, at: u64, code: &[u32]) {
    p.memory
        .write(
            at,
            &code
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    p.memory.protect(at, PAGE_SIZE, Permissions::RX).unwrap();
}
fn wait() -> [u32; 7] {
    [
        0xd2860000, 0xd2801001, 0xd2800002, 0xd2800003, 0xd2800c48, 0xd4000001, 0x14000000,
    ]
}

#[test]
fn time_observations_complete_on_source_with_faults_nulls_overlap_and_filter() {
    for (cpus, slots, filtered) in [(4, 4, false), (12, 12, false), (4, 1, false), (4, 1, true)] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; cpus];
        k.profile_syscalls = true;
        let mut root = process();
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
        root.memory.write(0x1800, &[0xa7; 16]).unwrap();
        let mut calls = vec![
            (169, 0x1000, 0x1100, 0),
            (169, 0, 0x1108, 0),
            (169, 0x1200, 0, 0),
            (169, 0x1210, 0x1218, 0),
            (169, 0x8ff8, 0x1800, 14),
            (169, 0x1800, 0x8ffc, 14),
            (169, 0, 0, 0),
        ];
        for (i, id) in [0, 1, 4, 5, 6, 7].into_iter().enumerate() {
            calls.push((113, id, 0x1500 + i as u32 * 32, 0));
            calls.push((114, id, 0, 0));
        }
        calls.push((113, 3, 0x8ff8, 14)); // Supported thread clock, invalid destination.
        calls.push((113, 2, 0x8ff8, 22)); // Process CPU clock remains unsupported.
        calls.push((114, 1, 0x8ff8, 14));
        let mut code = Vec::new();
        for (i, &(number, a0, a1, _)) in calls.iter().enumerate() {
            mov(&mut code, 0, a0);
            mov(&mut code, 1, a1);
            mov(&mut code, 8, number);
            code.push(0xd4000001);
            mov(&mut code, 9, 0x2000 + i as u32 * 8);
            code.push(0xf9000120); // str x0,[x9]
        }
        mov(&mut code, 0, 0x2800);
        mov(&mut code, 1, 1);
        code.push(0xb9000001);
        code.extend(wait());
        words(&mut root, 0x4000, &code);
        words(&mut root, 0x5000, &wait());
        let mut peer = root.fork();
        peer.vm_id = 2;
        peer.tgid = 2;
        peer.cpu.set_pc(0x5000);
        for p in [&root, &peer] {
            p.signals.io.scheduling.set_affinity((1 << slots) - 1);
        }
        k.processes.insert(1, root);
        k.processes.insert(2, peer);
        assert!(k
            .parallel_round(&mut trames_linux::CapturedOutput::default(), 1_000_000)
            .unwrap());
        let root = k.processes.read(&1);
        eprintln!("time CPUs={cpus} slots={slots} filtered={filtered} marker={:?} cohorts={} returned={:?}", root.memory.read_array::<4>(0x2800).unwrap(), k.parallel_rounds, k.cohort_return_syscalls);
        assert_eq!(
            root.memory.read_array::<4>(0x2800).unwrap(),
            1u32.to_le_bytes()
        );
        for (i, &(_, _, _, errno)) in calls.iter().enumerate() {
            assert_eq!(
                u64::from_le_bytes(root.memory.read_array::<8>(0x2000 + i as u64 * 8).unwrap()),
                0u64.wrapping_sub(errno as u64),
                "call {i}"
            );
        }
        for address in [0x1000, 0x1200] {
            assert!(
                u64::from_le_bytes(root.memory.read_array::<8>(address).unwrap()) > 1_700_000_000
            );
            assert!(
                u64::from_le_bytes(root.memory.read_array::<8>(address + 8).unwrap()) < 1_000_000
            );
        }
        assert_eq!(root.memory.read_array::<16>(0x1100).unwrap(), [0; 16]);
        assert_eq!(root.memory.read_array::<8>(0x1218).unwrap(), [0; 8]);
        assert_eq!(root.memory.read_array::<16>(0x1800).unwrap(), [0xa7; 16]);
        for (i, id) in [0, 1, 4, 5, 6, 7].into_iter().enumerate() {
            let at = 0x1500 + i as u64 * 32;
            let sec = u64::from_le_bytes(root.memory.read_array::<8>(at).unwrap());
            assert_eq!(sec > 1_700_000_000, matches!(id, 0 | 5));
            assert!(
                u64::from_le_bytes(root.memory.read_array::<8>(at + 8).unwrap()) < 1_000_000_000
            );
        }
        assert!(k.cohort_return_syscalls.is_empty());
        assert_eq!(k.parallel_rounds, 1);
        assert_eq!(k.vm_checkpoint_spaces, 0);
        assert_eq!(k.service_requests, 0);
    }
}
