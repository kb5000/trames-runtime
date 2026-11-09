// SPDX-License-Identifier: GPL-3.0-or-later
use super::tests::{kernel, process};
use super::*;
use trames_memory::{Permissions, PAGE_SIZE};

fn code<C: Cpu>(p: &mut Process<C>, at: u64, words: &[u32]) {
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
fn mov(words: &mut Vec<u32>, register: u32, value: u32) {
    words.push(0xd2800000 | ((value & 0xffff) << 5) | register);
    if value > 0xffff {
        words.push(0xf2a00000 | ((value >> 16) << 5) | register);
    }
}
fn wait() -> [u32; 7] {
    [
        0xd2860000, 0xd2801001, 0xd2800002, 0xd2800003, 0xd2800c48, 0xd4000001, 0x14000000,
    ]
}
#[test]
fn descriptor_ioctl_family_finishes_on_source_workers_without_joined_dispatch() {
    for (cpus, slots, filtered) in [(4, 4, false), (12, 12, false), (4, 1, false), (4, 1, true)] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; cpus];
        k.profile_syscalls = true;
        let mut root = process();
        root.linux.vfs.set_runtime_info(
            1,
            trames_vfs::RuntimeInfo {
                processes: vec![trames_vfs::ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        root.linux.vfs.enable_video_device();
        root.linux
            .vfs
            .configure_local_fabric(trames_vfs::NetworkMode::Loopback)
            .unwrap();
        let pipe = root.linux.vfs.pipe(0).unwrap()[0];
        let socket = root.linux.vfs.socket(2, 2, 0).unwrap();
        let render = root
            .linux
            .vfs
            .open_at(-100, b"/dev/dri/renderD128", 2, 0)
            .unwrap();
        let namespace = root
            .linux
            .vfs
            .open_at(-100, b"/proc/self/ns/net", 0, 0)
            .unwrap();
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
        root.memory.write(0x1000, b"lo\0").unwrap();
        let mut body = Vec::new();
        for (fd, request, pointer, result) in [
            (pipe, 0x1234, 0, 19),
            (65535, 0x1234, 0, 20),
            (namespace, 0xb703, 0, 21),
            (socket, 0x8933, 0x1000, 22),
            (render, 0xc0406400, 0x1100, 23),
            (pipe, 0x5402, 0, 24),
            (namespace, 0x1234, 0, 25),
        ] {
            mov(&mut body, 0, fd);
            mov(&mut body, 1, request);
            mov(&mut body, 2, pointer);
            mov(&mut body, 8, 29);
            body.push(0xd4000001);
            body.push(0xaa0003e0 | result);
        }
        mov(&mut body, 0, 0x2800);
        mov(&mut body, 1, 1);
        body.push(0xb9000001);
        body.extend(wait());
        code(&mut root, 0x4000, &body);
        code(&mut root, 0x5000, &wait());
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
        eprintln!("ioctl CPUs={cpus} slots={slots} filtered={filtered} marker={:?} cohorts={} scopes={} returned={:?}",root.memory.read_array::<4>(0x2800).unwrap(),k.parallel_rounds,k.vm_checkpoint_spaces,k.cohort_return_syscalls);
        assert_eq!(
            root.memory.read_array::<4>(0x2800).unwrap(),
            1u32.to_le_bytes()
        );
        assert_eq!(root.cpu.x(19), 0u64.wrapping_sub(25));
        assert_eq!(root.cpu.x(20), 0u64.wrapping_sub(9));
        assert_eq!(root.cpu.x(21), 0x40000000);
        assert_eq!(root.cpu.x(22), 0);
        assert_eq!(root.cpu.x(23), 0);
        assert_eq!(root.cpu.x(24), 0u64.wrapping_sub(25));
        assert_eq!(root.cpu.x(25), 0u64.wrapping_sub(25));
        assert_eq!(
            root.memory.read_array::<4>(0x1010).unwrap(),
            1u32.to_le_bytes()
        );
        assert_eq!(
            root.memory.read_array::<4>(0x1100).unwrap(),
            1u32.to_le_bytes()
        );
        assert_eq!(k.parallel_rounds, 1);
        assert_eq!(k.service_requests, 0);
        assert_eq!(k.vm_checkpoint_spaces, 0);
        assert!(
            k.cohort_return_syscalls.is_empty(),
            "{:?}",
            k.cohort_return_syscalls
        );
    }
}
