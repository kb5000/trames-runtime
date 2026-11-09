// SPDX-License-Identifier: GPL-3.0-or-later
//! Original per-task observations do not require a host-global memory provider.
use super::tests::{kernel, process};
use super::*;
use trames_memory::{Permissions, PAGE_SIZE};

fn imm(code: &mut Vec<u32>, r: u32, value: u64) {
    code.push(0xd2800000 | ((value as u16 as u32) << 5) | r);
    for shift in 1..4 {
        let word = ((value >> (shift * 16)) & 0xffff) as u32;
        if word != 0 {
            code.push(0xf2800000 | (shift << 21) | (word << 5) | r);
        }
    }
}
fn call(code: &mut Vec<u32>, nr: u32, args: [u64; 6], file: bool, result: u64) {
    for (r, value) in args.into_iter().enumerate() {
        imm(code, r as u32, value);
    }
    if file {
        code.push(0xaa1403e0);
    }
    imm(code, 8, nr as u64);
    code.push(0xd4000001);
    imm(code, 9, result);
    code.push(0xf9000120);
}

#[test]
fn accepted_task_memory_files_keep_live_original_mm_and_retire_without_pid_or_fd_donation() {
    use trames_vfs::{FileCommand, FileOutcome, FileValue, FileWork};
    for path in [b"/proc/1/status".as_slice(), b"/proc/1/statm"] {
        let mut k = kernel();
        k.memory_limits = crate::MemoryLimits::host_managed();
        let mut p = process();
        p.memory.write(0x1000, b"original").unwrap();
        k.install_proc_source(&p, None);
        k.publish_task(1, &p);
        let source = k.proc_source.as_ref().unwrap().clone();
        let old_task = Arc::downgrade(&p.signals.io);
        let paths = p.linux.vfs.path_queries();
        let fd = paths
            .open_at_resolve(-100, path, 0, 0, 0, &Default::default())
            .unwrap()
            .unwrap();
        let target = p
            .linux
            .vfs
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        let read = || match FileWork::new(
            &paths,
            target.clone(),
            FileCommand::Read {
                count: 65536,
                offset: Some(0),
            },
        )
        .run()
        {
            FileOutcome::Complete(reply) => reply.result.map(|value| match value {
                FileValue::Bytes(bytes) => bytes,
                _ => panic!("proc bytes"),
            }),
            _ => panic!("original task metadata has no owner or disk wait"),
        };
        let rss = |bytes: Vec<u8>| {
            let text = String::from_utf8(bytes).unwrap();
            if path.ends_with(b"/status") {
                text.lines()
                    .find(|line| line.starts_with("VmRSS:"))
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
                    * 1024
            } else {
                text.split_whitespace()
                    .nth(1)
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
                    * PAGE_SIZE
            }
        };
        assert_eq!(rss(read().unwrap()), p.memory.resident_bytes() as u64);
        p.linux.vfs.close(fd).unwrap();
        assert_eq!(p.linux.vfs.eventfd(99, 0).unwrap(), fd);
        p.memory.write(0x2000, b"later resident").unwrap();
        assert_eq!(rss(read().unwrap()), p.memory.resident_bytes() as u64);
        p.signals.io.exit();
        drop(p);
        let mut replacement = process();
        replacement.signals.io_directory = source.directory.clone();
        replacement.linux.command_name.set(b"replacement");
        k.publish_task(1, &replacement);
        assert!(
            old_task.upgrade().is_none(),
            "an accepted proc file retained its task/Files"
        );
        assert_eq!(
            read(),
            Err(Errno(3)),
            "original dead PID must not select its replacement"
        );
    }
}

#[test]
fn complete_task_proc_memory_family_and_uring_use_original_resources_without_host_statistics() {
    let paths: &[&[u8]] = &[
        b"/proc/self/status",
        b"/proc/1/stat",
        b"/proc/1/statm",
        b"/proc/1/smaps",
        b"/proc/1/smaps_rollup",
        b"/proc/thread-self/maps",
    ];
    for (cpus, slots) in [(4, 4), (12, 12), (4, 1)] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; cpus];
        k.memory_limits = crate::MemoryLimits::host_managed();
        k.profile_syscalls = true;
        let mut root = process();
        root.memory
            .map(0x100000, paths.len() as u64 * PAGE_SIZE, Permissions::RW)
            .unwrap();
        let (fd, ring) = root.linux.vfs.uring_create(8, 16).unwrap();
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
        let mut code = Vec::new();
        for (i, path) in paths.iter().enumerate() {
            let path_at = 0x1000 + i as u64 * 128;
            let out = 0x100000 + i as u64 * PAGE_SIZE;
            let row = 0x2000 + i as u64 * 64;
            root.memory.write(path_at, path).unwrap();
            root.memory
                .write(path_at + path.len() as u64, &[0])
                .unwrap();
            root.memory
                .write_array(0x3000 + i as u64 * 16, out.to_le_bytes())
                .unwrap();
            root.memory
                .write_array(0x3008 + i as u64 * 16, 1024u64.to_le_bytes())
                .unwrap();
            call(
                &mut code,
                56,
                [(-100i64) as u64, path_at, 0, 0, 0, 0],
                false,
                row,
            );
            code.push(0xaa0003f4);
            call(&mut code, 80, [0, 0x1800, 0, 0, 0, 0], true, row + 8);
            call(&mut code, 63, [0, out, 1024, 0, 0, 0], true, row + 16);
            call(
                &mut code,
                67,
                [0, out + 1024, 1024, 0, 0, 0],
                true,
                row + 24,
            );
            call(&mut code, 62, [0, 0, 0, 0, 0, 0], true, 0x2a00);
            call(
                &mut code,
                65,
                [0, 0x3000 + i as u64 * 16, 1, 0, 0, 0],
                true,
                row + 32,
            );
            call(
                &mut code,
                291,
                [(-100i64) as u64, path_at, 0, 0x7ff, 0x1800, 0],
                false,
                row + 40,
            );
            let mut sqe = [0u8; 64];
            sqe[0] = 22;
            sqe[16..24].copy_from_slice(&(out + 2048).to_le_bytes());
            sqe[24..28].copy_from_slice(&1024u32.to_le_bytes());
            sqe[32..40].copy_from_slice(&(300 + i as u64).to_le_bytes());
            root.memory.write(0x20000 + i as u64 * 64, &sqe).unwrap();
            root.memory
                .write_array(
                    0x10000 + trames_vfs::URING_SQ_ARRAY as u64 + i as u64 * 4,
                    (i as u32).to_le_bytes(),
                )
                .unwrap();
            imm(&mut code, 9, 0x20004 + i as u64 * 64);
            code.push(0xb9000134);
            imm(&mut code, 9, 0x10004);
            imm(&mut code, 10, i as u64 + 1);
            code.push(0x889ffd2a);
            call(&mut code, 426, [fd as u64, 1, 1, 1, 0, 0], false, row + 56);
            imm(&mut code, 9, 0x10040);
            imm(&mut code, 10, i as u64 + 1);
            code.push(0x889ffd2a);
            call(&mut code, 57, [0; 6], true, row + 48);
        }
        imm(&mut code, 0, 0x2800);
        imm(&mut code, 1, 1);
        code.push(0xb9000001);
        let sleep = [
            0xd2860000, 0xd2801001, 0xd2800002, 0xd2800003, 0xd2800c48, 0xd4000001, 0x14000000,
        ];
        code.extend(sleep);
        for (address, words) in [(0x4000, code.as_slice()), (0x6000, sleep.as_slice())] {
            root.memory
                .write(
                    address,
                    &words
                        .iter()
                        .flat_map(|w| w.to_le_bytes())
                        .collect::<Vec<_>>(),
                )
                .unwrap();
        }
        root.memory
            .protect(0x4000, 3 * PAGE_SIZE, Permissions::RX)
            .unwrap();
        k.install_proc_source(&root, None);
        let mut peer = root.fork();
        peer.vm_id = 2;
        peer.tgid = 2;
        peer.cpu.set_pc(0x6000);
        for p in [&root, &peer] {
            p.signals.io.scheduling.set_affinity((1 << slots) - 1);
        }
        k.processes.insert(1, root);
        k.processes.insert(2, peer);
        assert!(k
            .parallel_epoch(
                &mut trames_linux::CapturedOutput::default(),
                1_000_000,
                true
            )
            .unwrap());
        let root = k.processes.get_mut(&1).unwrap();
        eprintln!(
            "original task-proc CPUs={cpus} slots={slots} cohorts={} returned={:?} marker={:?}",
            k.parallel_rounds,
            k.cohort_return_syscalls,
            root.memory.read_array::<4>(0x2800).unwrap()
        );
        assert_eq!(
            root.memory.read_array::<4>(0x2800).unwrap(),
            1u32.to_le_bytes()
        );
        for (i, path) in paths.iter().enumerate() {
            let row = 0x2000 + i as u64 * 64;
            if matches!(*path, b"/proc/1/smaps" | b"/proc/1/smaps_rollup") {
                // These files are not implemented. Preserve canonical ENOENT,
                // EBADF and CQ results without a capability/cohort fallback.
                assert_eq!(root.memory.read_u64(row).unwrap(), 0u64.wrapping_sub(2));
                for offset in [8, 16, 24, 32, 48] {
                    assert_eq!(
                        root.memory.read_u64(row + offset).unwrap(),
                        0u64.wrapping_sub(9)
                    );
                }
                assert_eq!(
                    root.memory.read_u64(row + 40).unwrap(),
                    0u64.wrapping_sub(2)
                );
                assert_eq!(
                    i32::from_le_bytes(ring.read_queue::<4>(trames_vfs::URING_CQES + i * 16 + 8)),
                    -9
                );
                continue;
            }
            assert!(
                (3..64).contains(&root.memory.read_u64(row).unwrap()),
                "{path:?}"
            );
            for offset in [8, 40, 48] {
                assert_eq!(
                    root.memory.read_u64(row + offset).unwrap(),
                    0,
                    "{path:?} at {offset}"
                );
            }
            for offset in [16, 24, 32] {
                let n = root.memory.read_u64(row + offset).unwrap();
                assert!((1..=1024).contains(&n), "{path:?} at {offset} got {n}");
            }
            assert_eq!(root.memory.read_u64(row + 56).unwrap(), 1);
            assert_eq!(
                ring.read_queue::<8>(trames_vfs::URING_CQES + i * 16),
                (300 + i as u64).to_le_bytes()
            );
            let n = i32::from_le_bytes(ring.read_queue::<4>(trames_vfs::URING_CQES + i * 16 + 8));
            assert!((1..=1024).contains(&n), "{path:?} uring result {n}");
        }
        assert_eq!(k.parallel_rounds, 1);
        assert!(k.cohort_return_syscalls.is_empty());
        assert_eq!(k.service_requests, 0);
        assert_eq!(k.vm_checkpoint_groups, 0);
    }
}
