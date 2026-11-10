// SPDX-License-Identifier: GPL-3.0-or-later
use super::tests::{admitted_process, kernel};
use super::*;
use trames_memory::{Permissions, PAGE_SIZE};
type Process = super::Process<trames_cpu::Cpu>;
type Kernel = super::Kernel<trames_cpu::Cpu>;
const UPPER: u64 = 1 << 32;
fn mov(code: &mut Vec<u32>, r: u32, value: u64) {
    code.push(0xd2800000 | ((value as u16 as u32) << 5) | r);
    for shift in 1..4 {
        let n = ((value >> (shift * 16)) & 0xffff) as u32;
        if n != 0 {
            code.push(0xf2800000 | (shift << 21) | (n << 5) | r);
        }
    }
}
fn call(code: &mut Vec<u32>, nr: u32, args: [u64; 6]) {
    for (r, value) in args.into_iter().enumerate() {
        mov(code, r as u32, value);
    }
    mov(code, 8, UPPER | nr as u64);
    code.push(0xd4000001);
}
fn park(code: &mut Vec<u32>) {
    call(code, 98, [0x3400, 128, 0, 0, 0, 0]);
    code.push(0x14000000);
}
fn code(p: &mut Process, at: u64, words: &[u32]) {
    for (i, word) in words.iter().enumerate() {
        p.memory
            .write_array(at + i as u64 * 4, word.to_le_bytes())
            .unwrap();
    }
    let length = (words.len() as u64 * 4).div_ceil(PAGE_SIZE) * PAGE_SIZE;
    p.memory.protect(at, length, Permissions::RX).unwrap();
}
fn filtered(k: &mut Kernel, p: &mut Process) {
    // Permit ring commands only when the original raw selector has upper word
    // one. This proves BPF sees the entry registers, not normalized ABI values.
    let program = [
        (0x20u16, 0u8, 0u8, 0u32),
        (0x15, 0, 3, 427),
        (0x20, 0, 0, 28),
        (0x15, 1, 0, 1),
        (6, 0, 0, 0x50007),
        (6, 0, 0, 0x7fff0000),
    ];
    p.memory
        .write_array(0x1300, [6, 0, 0, 0, 0, 0, 0, 0, 0, 0x14, 0, 0, 0, 0, 0, 0])
        .unwrap();
    for (i, (code, jt, jf, value)) in program.into_iter().enumerate() {
        let mut bytes = [0; 8];
        bytes[..2].copy_from_slice(&code.to_le_bytes());
        bytes[2] = jt;
        bytes[3] = jf;
        bytes[4..].copy_from_slice(&value.to_le_bytes());
        p.memory.write_array(0x1400 + i as u64 * 8, bytes).unwrap();
    }
    p.linux.vfs.credentials.caps.no_new_privs.set();
    assert_eq!(k.seccomp(p, [1, 0, 0x1300, 0, 0, 0]), Ok(0));
}

#[test]
fn complete_structural_family_and_ring_controls_share_one_original_dispatch_contract() {
    for (cpus, slots, filter) in [(4, 4, false), (12, 12, false), (4, 1, false), (4, 1, true)] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; cpus];
        k.profile_syscalls = true;
        let mut root = admitted_process(&k);
        let (ring, _) = root.linux.vfs.uring_create(4, 8).unwrap();
        assert_eq!(ring, 3);
        let event = root.linux.vfs.eventfd(0, 0).unwrap();
        assert_eq!(event, 4);
        root.linux
            .vfs
            .import_file(b"/original", b"x".to_vec())
            .unwrap();
        let file = root.linux.vfs.open_at(-100, b"/original", 2, 0).unwrap();
        assert_eq!(file, 5);
        root.memory
            .write_array(0x1600, 0x2000u64.to_le_bytes())
            .unwrap();
        root.memory
            .write_array(0x1608, PAGE_SIZE.to_le_bytes())
            .unwrap();
        root.memory.write_array(0x1700, file.to_le_bytes()).unwrap();
        root.memory
            .write_array(0x1718, 0x1720u64.to_le_bytes())
            .unwrap();
        root.memory
            .write_array(0x1720, (-2i32).to_le_bytes())
            .unwrap();
        root.memory
            .write_array(0x1730, event.to_le_bytes())
            .unwrap();
        root.memory
            .write_array(0x1b00, 0x2000u64.to_le_bytes())
            .unwrap();
        root.memory.write_array(0x1b08, 4u32.to_le_bytes()).unwrap();
        root.memory.write_array(0x1b0c, 7u16.to_le_bytes()).unwrap();
        root.memory.write_array(0x1b40, 7u32.to_le_bytes()).unwrap();
        root.memory.write_array(0x1b8c, 7u16.to_le_bytes()).unwrap();
        if filter {
            filtered(&mut k, &mut root);
        }
        let mut calls = vec![
            (214, [0, 0, 0, 0, 0, 0], 0xa000i64),
            (214, [0xb000, 0, 0, 0, 0, 0], 0xb000),
            (214, [0xa000, 0, 0, 0, 0, 0], 0xa000),
            (222, [0x10000, 8192, 3, 0x32, u64::MAX, 0], 0x10000),
            (226, [0x10000, 4096, 1, 0, 0, 0], 0),
            (232, [0x10000, 8192, 0x1800, 0, 0, 0], 0),
            (233, [0x10000, 8192, UPPER | 4, 0, 0, 0], 0),
            (226, [0x10000, 8192, 3, 0, 0, 0], 0),
            (216, [0x10000, 8192, 12288, 1, 0, 0], 0x10000),
            (215, [0x10000, 12288, 0, 0, 0, 0], 0),
            (220, [u64::MAX; 6], -22),
            (221, [u64::MAX; 6], -14),
            (281, [u64::MAX; 6], -14),
            (425, [4, 0x1000, 0, 0, 0, 0], 6),
            (57, [6, 0, 0, 0, 0, 0], 0),
        ];
        for (op, address, count, result) in [
            (0, 0x1600, 1, 0),
            (0, 0x1600, 1, -16),
            (1, 0, 0, 0),
            (2, 0x1700, 1, 0),
            (6, 0x1710, 1, 1),
            (4, 0x1730, 1, 0),
            (5, 0, 0, 0),
            (5, 0, 0, -6),
            (8, 0x1800, 64, 0),
            (3, 0, 0, 0),
            (22, 0x1b00, 1, 0),
            (26, 0x1b40, 1, 0),
            (23, 0x1b80, 1, 0),
            (u32::MAX, 0, 0, -22),
        ] {
            calls.push((
                427,
                [ring as u64, UPPER | op as u64, address, UPPER | count, 0, 0],
                result,
            ));
        }
        calls.push((
            427,
            [ring as u64, 42, 0, 0, 0, 0],
            if filter { -7 } else { -22 },
        ));
        let mut words = Vec::new();
        mov(&mut words, 24, 0x3000);
        for (i, (nr, args, _)) in calls.iter().enumerate() {
            call(&mut words, *nr, *args);
            words.push(0xf9000300 | ((i as u32) << 10));
        }
        mov(&mut words, 0, 0x3800);
        mov(&mut words, 1, 1);
        words.push(0xb9000001);
        park(&mut words);
        code(&mut root, 0x4000, &words);
        let mut peer_code = Vec::new();
        park(&mut peer_code);
        code(&mut root, 0x7000, &peer_code);
        let mut peer = root.fork();
        peer.vm_id = 2;
        peer.tgid = 100;
        peer.cpu.set_pc(0x7000);
        k.install_proc_source(&root, None);
        k.publish_task(1, &root);
        k.publish_task(100, &peer);
        k.processes.insert(1, root);
        k.processes.insert(100, peer);
        assert!(k
            .parallel_round(&mut trames_linux::CapturedOutput::default(), 1_000_000)
            .unwrap());
        let p = k.processes.read(&1);
        assert_eq!(
            p.memory.read_array::<4>(0x3800).unwrap(),
            1u32.to_le_bytes(),
            "cpus={cpus} slots={slots} filter={filter} returned={:?}",
            k.cohort_return_syscalls
        );
        for (i, (nr, args, expected)) in calls.iter().enumerate() {
            assert_eq!(
                p.memory.read_u64(0x3000 + i as u64 * 8).unwrap(),
                *expected as u64,
                "nr={nr} args={args:?} cpus={cpus} slots={slots} filter={filter}"
            );
        }
        assert_eq!(k.parallel_rounds, 1);
        assert_eq!(k.service_requests, 0);
        assert!(
            k.cohort_return_syscalls.is_empty(),
            "{:?}",
            k.cohort_return_syscalls
        );
        if filter {
            assert_eq!(
                p.seccomp.evaluations(),
                k.syscalls,
                "one BPF decision per accepted entry, including both original CPUs"
            );
        }
        assert!(p.linux.vfs.flags(6).is_err());
        assert!(p.linux.vfs.flags(file).is_ok());
    }
}
fn image(words: &[u32]) -> Vec<u8> {
    let mut bytes = vec![0u8; 256 + words.len() * 4];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (at, n) in [(16, 2u16), (18, 183), (52, 64), (54, 56), (56, 1)] {
        bytes[at..at + 2].copy_from_slice(&n.to_le_bytes());
    }
    for (at, n) in [(20, 1u32), (64, 1), (68, 5)] {
        bytes[at..at + 4].copy_from_slice(&n.to_le_bytes());
    }
    let len = bytes.len() as u64;
    for (at, n) in [
        (24, 0x400100u64),
        (32, 64),
        (80, 0x400000),
        (96, len),
        (104, len),
        (112, 4096),
    ] {
        bytes[at..at + 8].copy_from_slice(&n.to_le_bytes());
    }
    for (i, n) in words.iter().enumerate() {
        bytes[256 + i * 4..260 + i * 4].copy_from_slice(&n.to_le_bytes());
    }
    bytes
}
#[test]
fn valid_clone_and_both_exec_forms_keep_the_original_structural_call_through_replacement() {
    for at in [false, true] {
        for slots in [1, 4, 12] {
            let mut k = kernel();
            k.cpu_count = slots.max(4);
            k.workers = crate::workers::Pool::new(slots);
            k.per_cpu = vec![Duration::ZERO; k.cpu_count];
            k.profile_syscalls = true;
            let mut root = admitted_process(&k);
            let mut exit = Vec::new();
            call(&mut exit, 93, [7, 0, 0, 0, 0, 0]);
            root.linux
                .vfs
                .import_executable(b"/next", image(&exit))
                .unwrap();
            root.memory.write(0x1200, b"/next\0").unwrap();
            let mut words = Vec::new();
            call(&mut words, 220, [17, 0, 0, 0, 0, 0]);
            let branch = words.len();
            words.push(0);
            words.push(0xaa0003f4);
            mov(&mut words, 1, 0x2800);
            mov(&mut words, 2, 0);
            mov(&mut words, 3, 0);
            mov(&mut words, 8, UPPER | 260);
            words.push(0xd4000001);
            words.push(0xaa0003f3);
            mov(&mut words, 0, 0x3800);
            mov(&mut words, 1, 1);
            words.push(0xb9000001);
            park(&mut words);
            let child = words.len();
            words[branch] = 0xb4000000 | (((child - branch) as u32) << 5);
            call(
                &mut words,
                if at { 281 } else { 221 },
                if at {
                    [(-100i64) as u64, 0x1200, 0, 0, 0, 0]
                } else {
                    [0x1200, 0, 0, 0, 0, 0]
                },
            );
            call(&mut words, 93, [99, 0, 0, 0, 0, 0]);
            code(&mut root, 0x4000, &words);
            let mut peer_code = Vec::new();
            park(&mut peer_code);
            code(&mut root, 0x7000, &peer_code);
            let mut peer = root.fork();
            peer.vm_id = 2;
            peer.tgid = 100;
            peer.cpu.set_pc(0x7000);
            k.install_proc_source(&root, None);
            k.publish_task(1, &root);
            k.publish_task(100, &peer);
            k.processes.insert(1, root);
            k.processes.insert(100, peer);
            assert!(k
                .parallel_round(&mut trames_linux::CapturedOutput::default(), 2_000_000)
                .unwrap());
            let p = k.processes.read(&1);
            assert_eq!(
                p.memory.read_array::<4>(0x3800).unwrap(),
                1u32.to_le_bytes(),
                "at={at} slots={slots} returned={:?}",
                k.cohort_return_syscalls
            );
            assert_eq!(p.cpu.x(19), p.cpu.x(20));
            assert!(p.cpu.x(19) > 0);
            assert_eq!(
                p.memory.read_array::<4>(0x2800).unwrap(),
                (7u32 << 8).to_le_bytes()
            );
            assert_eq!(k.parallel_rounds, 1);
            assert_eq!(k.service_requests, 0);
            assert!(
                k.cohort_return_syscalls.is_empty(),
                "{:?}",
                k.cohort_return_syscalls
            );
        }
    }
}
