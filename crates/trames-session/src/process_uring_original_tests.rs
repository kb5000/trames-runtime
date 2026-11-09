// SPDX-License-Identifier: GPL-3.0-or-later
use super::tests::{kernel, process};
use super::*;
use trames_memory::{Permissions, PAGE_SIZE};

#[test]
fn nested_uring_interest_mutation_and_completion_stay_in_one_live_execution_cohort() {
    fn imm(code: &mut Vec<u32>, r: u32, value: u64) {
        code.push(0xd2800000 | ((value as u16 as u32) << 5) | r);
        for shift in 1..4 {
            let word = ((value >> (shift * 16)) & 0xffff) as u32;
            if word != 0 {
                code.push(0xf2800000 | (shift << 21) | (word << 5) | r);
            }
        }
    }
    fn call(code: &mut Vec<u32>, nr: u32, args: [u64; 6], result: u32) {
        for (r, value) in args.into_iter().enumerate() {
            imm(code, r as u32, value);
        }
        imm(code, 8, nr as u64);
        code.extend([0xd4000001, 0xaa0003e0 | result]);
    }
    for (cpus, slots) in [(4, 4), (12, 12), (4, 1)] {
        for getevents in [false, true] {
            let mut k = kernel();
            k.cpu_count = cpus;
            k.workers = crate::workers::Pool::new(slots);
            k.per_cpu = vec![Duration::ZERO; cpus];
            k.profile_syscalls = true;
            let mut root = process();
            let leaf = root.linux.vfs.eventfd(0, 0).unwrap();
            let child = root.linux.vfs.epoll_create(0).unwrap();
            let parent = root.linux.vfs.epoll_create(0).unwrap();
            root.linux.vfs.epoll_ctl(parent, 1, child, 1, 11).unwrap();
            let (fd, ring) = root.linux.vfs.uring_create(4, 8).unwrap();
            for (address, offset, len) in [
                (0x10000, 0, ring.ring_bytes),
                (0x20000, 0x10000000, ring.sqe_bytes),
            ] {
                root.memory
                    .map_backed(
                        address,
                        root.linux
                            .vfs
                            .mapping_pages(fd, offset, len, true, true)
                            .unwrap(),
                        true,
                        Permissions::RW,
                        false,
                    )
                    .unwrap();
            }
            let mut sqe = [0; 64];
            sqe[0] = 6;
            sqe[4..8].copy_from_slice(&parent.to_le_bytes());
            sqe[28..32].copy_from_slice(&1u32.to_le_bytes());
            sqe[32..40].copy_from_slice(&203u64.to_le_bytes());
            root.memory.write(0x20000, &sqe).unwrap();
            root.memory
                .write_array(0x10004, 1u32.to_le_bytes())
                .unwrap();
            root.memory.write_array(0x1300, 1u64.to_le_bytes()).unwrap();
            root.memory.write_array(0x1500, 1u32.to_le_bytes()).unwrap();
            root.memory
                .write_array(0x1508, 12u64.to_le_bytes())
                .unwrap();
            let mut first = Vec::new();
            call(
                &mut first,
                426,
                [
                    fd as u64,
                    1,
                    u64::from(getevents),
                    u64::from(getevents),
                    0,
                    0,
                ],
                20,
            );
            imm(&mut first, 0, 0x2800);
            imm(&mut first, 1, 1);
            first.push(0xb9000001);
            let mut sleep = Vec::new();
            call(&mut sleep, 98, [0x3000, 128, 0, 0, 0, 0], 23);
            sleep.push(0x14000000);
            first.extend_from_slice(&sleep);
            let mut second = Vec::new();
            // Observe actual SQ publication before changing the original graph.
            imm(&mut second, 9, 0x10000);
            second.extend([0xb940012a, 0x34ffffea]);
            call(
                &mut second,
                21,
                [child as u64, 1, leaf as u64, 0x1500, 0, 0],
                21,
            );
            call(&mut second, 64, [leaf as u64, 0x1300, 8, 0, 0, 0], 22);
            second.extend_from_slice(&sleep);
            for (address, words) in [(0x4000, first), (0x5000, second)] {
                root.memory
                    .write(
                        address,
                        &words
                            .into_iter()
                            .flat_map(u32::to_le_bytes)
                            .collect::<Vec<_>>(),
                    )
                    .unwrap();
            }
            root.memory
                .protect(0x4000, 2 * PAGE_SIZE, Permissions::RX)
                .unwrap();
            root.signals.io.scheduling.set_affinity((1 << slots) - 1);
            let mut peer = root.fork();
            peer.linux.vfs = root.linux.vfs.clone_with_resources(true, false);
            peer.memory = root.memory.share();
            peer.vm_id = root.vm_id;
            peer.tgid = 2;
            peer.cpu.set_pc(0x5000);
            peer.signals.io.scheduling.set_affinity((1 << slots) - 1);
            k.processes.insert(1, root);
            k.processes.insert(2, peer);
            assert!(k
                .parallel_epoch(
                    &mut trames_linux::CapturedOutput::default(),
                    1_000_000,
                    true
                )
                .unwrap());
            assert_eq!(k.processes.read(&1).cpu.x(20), 1);
            assert_eq!(k.processes.read(&2).cpu.x(21), 0);
            assert_eq!(k.processes.read(&2).cpu.x(22), 8);
            assert_eq!(
                k.processes
                    .get_mut(&1)
                    .unwrap()
                    .memory
                    .read_array::<4>(0x2800)
                    .unwrap(),
                1u32.to_le_bytes()
            );
            assert_eq!(ring.cq_ready(), 1);
            assert_eq!(
                ring.read_queue::<8>(trames_vfs::URING_CQES),
                203u64.to_le_bytes()
            );
            assert_eq!(
                ring.read_queue::<4>(trames_vfs::URING_CQES + 8),
                1u32.to_le_bytes()
            );
            assert_eq!(k.parallel_rounds, 1);
            assert_eq!(k.service_requests, 0);
            assert_eq!(k.vm_checkpoint_groups, 0);
            assert!(
                k.cohort_return_syscalls.is_empty(),
                "{:?}",
                k.cohort_return_syscalls
            );
        }
    }
}

#[test]
fn original_uring_body_keeps_accepted_resources_without_a_join_in_blocking_and_async_enter() {
    for (cpus, slots, filtered) in [(4, 4, false), (12, 12, false), (4, 1, false), (4, 1, true)] {
        for flags in [0, 1] {
            let mut k = kernel();
            k.cpu_count = cpus;
            k.workers = crate::workers::Pool::new(slots);
            k.per_cpu = vec![Duration::ZERO; cpus];
            k.profile_syscalls = true;
            let mut root = process();
            root.linux.vfs.set_runtime_info(1, Default::default());
            struct Unavailable;
            impl trames_vfs::ProcSource for Unavailable {
                fn available(&self, _: trames_vfs::ProcRefresh) -> bool {
                    false
                }
                fn observe(&self, _: trames_vfs::ProcQuery<'_>) -> trames_vfs::RuntimeInfo {
                    panic!("missing provider must not be invented")
                }
            }
            root.linux.vfs.set_proc_source(Arc::new(Unavailable));
            let file = root
                .linux
                .vfs
                .open_at(-100, b"/proc/version", 0, 0)
                .unwrap();
            let (fd, ring) = root.linux.vfs.uring_create(4, 8).unwrap();
            for (address, offset, len) in [
                (0x10000, 0, ring.ring_bytes),
                (0x20000, 0x10000000, ring.sqe_bytes),
            ] {
                root.memory
                    .map_backed(
                        address,
                        root.linux
                            .vfs
                            .mapping_pages(fd, offset, len, true, true)
                            .unwrap(),
                        true,
                        Permissions::RW,
                        false,
                    )
                    .unwrap();
            }
            root.memory.write_array(0x1300, file.to_le_bytes()).unwrap();
            for (i, value) in [fd as u64, 2, 0x1300, 1, 0, 0].into_iter().enumerate() {
                root.cpu.set_x(i, value);
            }
            root.cpu.set_x(8, 427);
            root.linux.dispatch_untraced(
                &mut root.cpu,
                &mut root.memory,
                &mut trames_linux::CapturedOutput::default(),
            );
            assert_eq!(root.cpu.x(0), 0);
            root.linux.vfs.close(file).unwrap();
            assert_eq!(root.linux.vfs.eventfd(99, 0).unwrap(), file);
            let mut sqe = [0; 64];
            sqe[0] = 22;
            sqe[1] = 1; // IOSQE_FIXED_FILE names the accepted original publication.
            sqe[16..24].copy_from_slice(&0x1200u64.to_le_bytes());
            sqe[24..28].copy_from_slice(&8u32.to_le_bytes());
            sqe[32..40].copy_from_slice(&77u64.to_le_bytes());
            root.memory.write(0x20000, &sqe).unwrap();
            root.memory
                .write_array(0x10004, 1u32.to_le_bytes())
                .unwrap();
            if filtered {
                root.memory
                    .write_array(0x1400, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0x15, 0, 0, 0, 0, 0, 0])
                    .unwrap();
                root.memory
                    .write_array(0x1500, [6, 0, 0, 0, 0, 0, 0xff, 0x7f])
                    .unwrap();
                root.linux.vfs.credentials.caps.no_new_privs.set();
                assert_eq!(k.seccomp(&mut root, [1, 0, 0x1400, 0, 0, 0]), Ok(0));
            }
            let mut code = Vec::new();
            for (number, args, result) in [(426, [fd, 1, 1, flags, 0, 0], 20)] {
                for (r, value) in args.into_iter().enumerate() {
                    code.push(0xd2800000 | (value << 5) | r as u32);
                }
                code.extend([0xd2800008 | (number << 5), 0xd4000001, 0xaa0003e0 | result]);
            }
            code.extend([0xd2850000, 0xd2800021, 0xb9000001]); // completion marker at 0x2800
            let wait = [
                0xd2860000, 0xd2801001, 0xd2800002, 0xd2800003, 0xd2800c48, 0xd4000001, 0x14000000,
            ];
            code.extend(wait);
            for (at, words) in [(0x4000, code.as_slice()), (0x5000, wait.as_slice())] {
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
            peer.cpu.set_pc(0x5000);
            for p in [&root, &peer] {
                p.signals.io.scheduling.set_affinity((1 << slots) - 1);
            }
            k.processes.insert(1, root);
            k.processes.insert(2, peer);
            assert!(k
                .parallel_round(&mut trames_linux::CapturedOutput::default(), 1_000_000)
                .unwrap());
            let mut root = k.processes.get_mut(&1).unwrap();
            eprintln!("original-uring CPUs={cpus} slots={slots} filtered={filtered} flags={flags} marker={:?} cohorts={} returned={:?}", root.memory.read_array::<4>(0x2800).unwrap(), k.parallel_rounds, k.cohort_return_syscalls);
            assert_eq!(
                root.memory.read_array::<4>(0x2800).unwrap(),
                1u32.to_le_bytes()
            );
            assert_eq!(root.cpu.x(20), 1);
            assert_eq!(root.memory.read_array::<8>(0x1200).unwrap(), *b"Linux ve");
            assert_eq!(ring.cq_ready(), 1);
            assert_eq!(
                ring.read_queue::<8>(trames_vfs::URING_CQES),
                77u64.to_le_bytes()
            );
            assert_eq!(
                ring.read_queue::<4>(trames_vfs::URING_CQES + 8),
                8u32.to_le_bytes()
            );
            assert_eq!(root.linux.vfs.read(file, 8).unwrap(), 99u64.to_le_bytes());
            assert!(!root.linux.uring_requires_owner());
            assert!(k.cohort_return_syscalls.is_empty());
            assert_eq!(k.parallel_rounds, 1);
            assert_eq!(k.service_requests, 0);
            assert_eq!(k.vm_checkpoint_groups, 0);
        }
    }
}
