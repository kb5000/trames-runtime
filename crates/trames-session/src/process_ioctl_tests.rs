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
fn binder_call_reply_parks_original_workers_with_one_or_many_cpu_slots() {
    use trames_vfs::binder::{abi as b, Ioctl, Started};
    fn word(out: &mut [u8], at: usize, value: u64) {
        out[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn wr<C: Cpu>(p: &mut Process<C>, address: u64, write: u64, size: u64, capacity: u64) {
        let mut header = [0; 48];
        word(&mut header, 0, size);
        word(&mut header, 16, write);
        word(&mut header, 24, capacity);
        word(&mut header, 40, 0x2000);
        p.memory.write(address, &header).unwrap();
    }
    fn binder<C: Cpu>(p: &mut Process<C>, owner: u32) -> u32 {
        p.linux.vfs.set_lock_owner(owner);
        let fd = p.linux.vfs.open_at(-100, b"/dev/binder", 2, 0).unwrap();
        let pages = p
            .linux
            .vfs
            .mapping_file(fd)
            .unwrap()
            .binder_pages(0x100000, 0, 0x10000, false)
            .unwrap()
            .unwrap();
        p.memory
            .map_backed(
                0x100000,
                pages,
                false,
                Permissions {
                    read: true,
                    write: false,
                    execute: false,
                },
                false,
            )
            .unwrap();
        fd
    }
    fn invoke(words: &mut Vec<u32>, fd: u32, address: u32) {
        mov(words, 0, fd);
        mov(words, 1, b::WRITE_READ);
        mov(words, 2, address);
        mov(words, 8, 29);
        words.push(0xd4000001);
    }
    for slots in [1, 4, 12] {
        let mut k = kernel();
        k.cpu_count = slots.max(4);
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; k.cpu_count];
        k.profile_syscalls = true;
        let mut service = process();
        service
            .linux
            .vfs
            .set_runtime_info(1, trames_vfs::RuntimeInfo::default());
        let mut client = service.fork();
        client.vm_id = 2;
        client.tgid = 2;
        let service_fd = binder(&mut service, 1);
        let client_fd = binder(&mut client, 2);
        service.memory.write(0x1000, &[0; 4]).unwrap();
        assert!(matches!(
            Ioctl::start(
                service.linux.vfs.binder_file(service_fd).unwrap().unwrap(),
                service.linux.vfs.descriptor_factory(),
                1,
                b::SET_CONTEXT_MGR,
                0x1000,
                &mut service.memory
            )
            .unwrap(),
            Started::Complete(0)
        ));
        service
            .memory
            .write(0x1100, &b::ENTER_LOOPER.to_le_bytes())
            .unwrap();
        wr(&mut service, 0x1000, 0x1100, 4, 0);
        let Started::Read(mut enter) = Ioctl::start(
            service.linux.vfs.binder_file(service_fd).unwrap().unwrap(),
            service.linux.vfs.descriptor_factory(),
            1,
            b::WRITE_READ,
            0x1000,
            &mut service.memory,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(enter.finish(&mut service.memory).unwrap(), Some(0));
        drop(enter);
        for (p, cmd, payload) in [
            (&mut service, b::REPLY, b"pong"),
            (&mut client, b::TRANSACTION, b"ping"),
        ] {
            let mut transaction = [0; 64];
            word(&mut transaction, 32, 4);
            word(&mut transaction, 48, 0x1700);
            p.memory
                .write(0x1500, &b::command(cmd, &transaction))
                .unwrap();
            p.memory.write(0x1700, payload).unwrap();
        }
        wr(&mut service, 0x1200, 0, 0, 256);
        wr(&mut service, 0x1280, 0x1500, 68, 0);
        wr(&mut client, 0x1200, 0x1500, 68, 8);
        wr(&mut client, 0x1280, 0, 0, 256);
        let mut serve = Vec::new();
        invoke(&mut serve, service_fd, 0x1200);
        serve.push(0xaa0003f3);
        invoke(&mut serve, service_fd, 0x1280);
        mov(&mut serve, 0, 0x2800);
        mov(&mut serve, 1, 1);
        serve.push(0xb9000001);
        serve.extend(wait());
        let mut call = Vec::new();
        invoke(&mut call, client_fd, 0x1200);
        invoke(&mut call, client_fd, 0x1280);
        call.push(0xaa0003f3);
        mov(&mut call, 0, 0x2038);
        call.push(0xf9400001);
        call.push(0xb9400022);
        mov(&mut call, 0, 0x2800);
        call.push(0xb9000002);
        call.extend(wait());
        code(&mut service, 0x4000, &serve);
        code(&mut client, 0x5000, &call);
        client.cpu.set_pc(0x5000);
        for p in [&service, &client] {
            p.signals.io.scheduling.set_affinity((1 << slots) - 1);
        }
        k.processes.insert(1, service);
        k.processes.insert(2, client);
        assert!(k
            .parallel_round(&mut trames_linux::CapturedOutput::default(), 1_000_000)
            .unwrap());
        assert_eq!(
            k.processes.read(&1).memory.read_array::<4>(0x2800).unwrap(),
            1u32.to_le_bytes()
        );
        assert_eq!(
            k.processes.read(&2).memory.read_array::<4>(0x2800).unwrap(),
            *b"pong"
        );
        assert_eq!(k.processes.read(&1).cpu.x(19), 0);
        assert_eq!(k.processes.read(&2).cpu.x(19), 0);
        assert_eq!(k.service_requests, 0);
        assert_eq!(k.vm_checkpoint_spaces, 0);
        assert!(
            k.cohort_return_syscalls.is_empty(),
            "{:?}",
            k.cohort_return_syscalls
        );
    }
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
