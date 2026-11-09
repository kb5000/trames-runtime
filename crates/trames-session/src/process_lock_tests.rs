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
fn call(code: &mut Vec<u32>, number: u64, args: [u64; 6]) {
    for (register, value) in args.into_iter().enumerate() {
        mov(code, register as u32, value);
    }
    mov(code, 8, number);
    code.push(0xd4000001);
}
fn finish(code: &mut Vec<u32>) {
    code.extend([0xd2850000, 0xd2800021, 0xb9000001]);
    code.extend([
        0xd2860000, 0xd2801001, 0xd2800002, 0xd2800003, 0xd2800c48, 0xd4000001, 0x14000000,
    ]);
}
fn program(p: &mut Process<trames_cpu::Cpu>, at: u64, words: &[u32]) {
    p.memory
        .write(
            at,
            &words
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    p.memory.protect(at, PAGE_SIZE, Permissions::RX).unwrap();
}
fn flock(kind: u16, whence: u16) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..2].copy_from_slice(&kind.to_le_bytes());
    bytes[2..4].copy_from_slice(&whence.to_le_bytes());
    bytes[16..24].copy_from_slice(&8u64.to_le_bytes());
    bytes
}
fn filter(k: &mut Kernel<trames_cpu::Cpu>, root: &mut Process<trames_cpu::Cpu>, enabled: bool) {
    if enabled {
        root.memory
            .write_array(0x1300, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0x14, 0, 0, 0, 0, 0, 0])
            .unwrap();
        root.memory
            .write_array(0x1400, [6, 0, 0, 0, 0, 0, 0xff, 0x7f])
            .unwrap();
        root.linux.vfs.credentials.caps.no_new_privs.set();
        assert_eq!(k.seccomp(root, [1, 0, 0x1300, 0, 0, 0]), Ok(0));
    }
}
fn check(k: &mut Kernel<trames_cpu::Cpu>, cpus: usize, slots: usize, filtered: bool) {
    assert!(k
        .parallel_round(&mut trames_linux::CapturedOutput::default(), 1_000_000)
        .unwrap());
    eprintln!(
        "file-lock CPUs={cpus} slots={slots} filter={filtered} cohorts={} returned={:?}",
        k.parallel_rounds, k.cohort_return_syscalls
    );
    for pid in [1, 2] {
        assert_eq!(
            k.processes
                .get_mut(&pid)
                .unwrap()
                .memory
                .read_array::<4>(0x2800)
                .unwrap(),
            1u32.to_le_bytes()
        );
    }
    assert_eq!(k.parallel_rounds, 1);
    assert!(k.cohort_return_syscalls.is_empty());
    assert_eq!(k.service_requests, 0);
    assert_eq!(k.vm_checkpoint_groups, 0);
}
#[test]
fn posix_ofd_and_directory_flock_contention_completes_on_original_source_workers() {
    for (cpus, slots, filtered) in [(4, 4, false), (12, 12, false), (4, 1, false), (4, 1, true)] {
        for kind in 0..3 {
            let mut k = kernel();
            k.cpu_count = cpus;
            k.workers = crate::workers::Pool::new(slots);
            k.per_cpu = vec![Duration::ZERO; cpus];
            k.profile_syscalls = true;
            let mut root = process();
            root.linux.vfs.set_lock_owner(1);
            let path = if kind == 2 {
                b"/".as_slice()
            } else {
                b"/file".as_slice()
            };
            let flags = if kind == 2 { 0 } else { 0x42 };
            let a = root.linux.vfs.open_at(-100, path, flags, 0o600).unwrap();
            let b = root
                .linux
                .vfs
                .open_at(-100, path, if kind == 2 { 0 } else { 2 }, 0)
                .unwrap();
            if kind != 2 {
                root.linux.vfs.seek(a, 3, 0).unwrap();
                root.linux.vfs.seek(b, 3, 0).unwrap();
            }
            root.memory.write_array(0x1800, flock(1, 1)).unwrap();
            filter(&mut k, &mut root, filtered);
            let mut acquire = Vec::new();
            let mut release = Vec::new();
            if kind == 2 {
                call(&mut acquire, 32, [a as u64, 2, 0, 0, 0, 0]);
                call(&mut release, 32, [b as u64, 8, 0, 0, 0, 0]);
            } else {
                call(
                    &mut acquire,
                    25,
                    [a as u64, if kind == 0 { 7 } else { 38 }, 0x1800, 0, 0, 0],
                );
                call(
                    &mut release,
                    25,
                    [b as u64, if kind == 0 { 6 } else { 37 }, 0x1800, 0, 0, 0],
                );
            }
            acquire.push(0xaa0003f4);
            release.push(0xaa0003f4);
            finish(&mut acquire);
            finish(&mut release);
            program(&mut root, 0x4000, &acquire);
            program(&mut root, 0x5000, &release);
            let mut peer = root.fork();
            peer.vm_id = 2;
            peer.tgid = 2;
            peer.cpu.set_pc(0x5000);
            peer.linux.vfs.set_lock_owner(2);
            peer.memory.write_array(0x1800, flock(2, 1)).unwrap();
            if kind == 2 {
                peer.linux.vfs.flock(b, 6).unwrap();
            } else {
                let locked = if kind == 0 {
                    peer.linux.vfs.normalize_lock(b, 1, 1, 0, 8)
                } else {
                    peer.linux.vfs.normalize_ofd_lock(b, 1, 1, 0, 8)
                }
                .unwrap();
                peer.linux.vfs.record_lock_set(b, locked).unwrap();
            }
            k.processes.insert(1, root);
            k.processes.insert(2, peer);
            check(&mut k, cpus, slots, filtered);
            for pid in [1, 2] {
                assert_eq!(k.processes.get(&pid).unwrap().cpu.x(20), 0);
            }
        }
    }
}
#[test]
fn posix_deadlock_graph_spans_original_workers_and_releases_the_surviving_waiter() {
    for (cpus, slots, filtered) in [(4, 4, false), (12, 12, false), (4, 1, false), (4, 1, true)] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; cpus];
        k.profile_syscalls = true;
        let mut root = process();
        root.linux.vfs.set_lock_owner(1);
        let a = root.linux.vfs.open_at(-100, b"/a", 0x42, 0o600).unwrap();
        let b = root.linux.vfs.open_at(-100, b"/b", 0x42, 0o600).unwrap();
        root.memory.write_array(0x1800, flock(1, 0)).unwrap();
        root.memory.write_array(0x1840, flock(2, 0)).unwrap();
        filter(&mut k, &mut root, filtered);
        for (address, acquire, release) in [(0x4000, b, a), (0x5000, a, b)] {
            let mut code = Vec::new();
            call(&mut code, 25, [acquire as u64, 7, 0x1800, 0, 0, 0]);
            code.push(0xaa0003f4);
            call(&mut code, 25, [release as u64, 6, 0x1840, 0, 0, 0]);
            finish(&mut code);
            program(&mut root, address, &code);
        }
        let mut peer = root.fork();
        peer.vm_id = 2;
        peer.tgid = 2;
        peer.cpu.set_pc(0x5000);
        peer.linux.vfs.set_lock_owner(2);
        for (p, fd) in [(&root, a), (&peer, b)] {
            let lock = p.linux.vfs.normalize_lock(fd, 1, 0, 0, 8).unwrap();
            p.linux.vfs.record_lock_set(fd, lock).unwrap();
        }
        k.processes.insert(1, root);
        k.processes.insert(2, peer);
        check(&mut k, cpus, slots, filtered);
        let mut results = [
            k.processes.get(&1).unwrap().cpu.x(20),
            k.processes.get(&2).unwrap().cpu.x(20),
        ];
        results.sort();
        assert_eq!(results, [0, (-35i64) as u64]);
    }
}
