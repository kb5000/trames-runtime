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
fn complete_fd_control_uses_original_credentials_and_seals_without_joined_dispatch() {
    for (cpus, slots, filtered) in [(4, 4, false), (12, 12, false), (4, 1, false), (4, 1, true)] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; cpus];
        k.profile_syscalls = true;
        let mut root = process();
        let v = &mut root.linux.vfs;
        v.import_file(b"/owned", b"original".to_vec()).unwrap();
        v.import_file(b"/foreign", Vec::new()).unwrap();
        let owned = v.open_at(-100, b"/owned", 2, 0).unwrap();
        v.chown_fd(owned, 1000, 1000).unwrap();
        let alias = v.dup(owned, 0, false).unwrap();
        let foreign = v.open_at(-100, b"/foreign", 2, 0).unwrap();
        let path = v.open_at(-100, b"/", trames_vfs::O_PATH, 0).unwrap();
        let seal = v.memfd_create(b"readonly", 2).unwrap();
        v.write(seal, b"payload").unwrap();
        let busy = v.memfd_create(b"writable", 2).unwrap();
        v.truncate_fd(busy, PAGE_SIZE).unwrap();
        for (fd, address, writable) in [(seal, 0x10000, false), (busy, 0x11000, true)] {
            root.memory
                .map_backed(
                    address,
                    v.mapping_pages(fd, 0, PAGE_SIZE, writable, writable)
                        .unwrap(),
                    writable,
                    if writable {
                        Permissions::RW
                    } else {
                        Permissions::R
                    },
                    false,
                )
                .unwrap();
        }
        v.credentials = trames_vfs::Credentials::user(1000, 1000);
        v.credentials.suid = 2000;
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
        let mut fcntl = |fd, cmd, arg, result: i64| {
            calls.push((25, [fd as u64, cmd, arg, 0, 0, 0], result as u64))
        };
        let noatime = trames_vfs::O_NOATIME as u64;
        fcntl(owned, 4, noatime, 0);
        fcntl(alias, 3, 0, (noatime | 2) as i64);
        fcntl(foreign, 4, noatime, -1);
        fcntl(foreign, 4, noatime | 0x80000000, -1);
        fcntl(owned, 4, 0x80000000, -22);
        fcntl(path, 4, u64::MAX, -9);
        fcntl(owned, 12, u64::MAX, -22);
        fcntl(path, 12, u64::MAX, -9);
        fcntl(u32::MAX, 12, u64::MAX, -9);
        fcntl(owned, 0x100000003, 0, -22);
        fcntl(path, 1034, 0, -9);
        fcntl(foreign, 1034, 0, -22);
        fcntl(seal, 1034, 0, 0);
        fcntl(seal, 1033, 16, -22);
        fcntl(seal, 1033, 6, 0);
        fcntl(seal, 1034, 0, 6);
        fcntl(busy, 1033, 8, -16);
        fcntl(busy, 1034, 0, 0);
        fcntl(seal, 1033, 8, 0);
        fcntl(seal, 1034, 0, 14);
        fcntl(seal, 1033, 1, 0);
        fcntl(seal, 1034, 0, 15);
        fcntl(seal, 1033, 0, -1);
        calls.extend([
            (151, [2000, 0, 0, 0, 0, 0], 1000),
            (25, [owned as u64, 4, noatime, 0, 0, 0], 0),
            (25, [owned as u64, 4, 0, 0, 0, 0], 0),
            (25, [owned as u64, 4, noatime, 0, 0, 0], (-1i64) as u64),
            (151, [1000, 0, 0, 0, 0, 0], 2000),
            (25, [owned as u64, 4, noatime, 0, 0, 0], 0),
        ]);
        let mut code = Vec::new();
        mov(&mut code, 24, 0x1800);
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
        for (address, words) in [(0x4000, code.as_slice()), (0x6000, wait.as_slice())] {
            root.memory
                .write(
                    address,
                    &words
                        .iter()
                        .flat_map(|w| w.to_le_bytes())
                        .collect::<Vec<_>>(),
                )
                .unwrap();
            root.memory
                .protect(address, PAGE_SIZE, Permissions::RX)
                .unwrap();
        }
        let mut peer = root.fork();
        peer.vm_id = 2;
        peer.tgid = 2;
        peer.cpu.set_pc(0x6000);
        k.processes.insert(1, root);
        k.processes.insert(2, peer);
        assert!(k
            .parallel_round(&mut trames_linux::CapturedOutput::default(), 1_000_000)
            .unwrap());
        let root = k.processes.get_mut(&1).unwrap();
        eprintln!("fcntl CPUs={cpus} slots={slots} filter={filtered} cohorts={} returned={:?} marker={:?}",k.parallel_rounds,k.cohort_return_syscalls,root.memory.read_array::<4>(0x2800).unwrap());
        assert_eq!(
            root.memory.read_array::<4>(0x2800).unwrap(),
            1u32.to_le_bytes()
        );
        for (i, (_, args, result)) in calls.iter().enumerate() {
            assert_eq!(
                root.memory.read_u64(0x1800 + i as u64 * 8).unwrap(),
                *result,
                "call {i}: {args:?}"
            );
        }
        assert_eq!(
            root.linux.vfs.flags(alias).unwrap(),
            2 | trames_vfs::O_NOATIME
        );
        assert_eq!(root.linux.vfs.seals(busy, None), Ok(0));
        assert_eq!(root.linux.vfs.seals(seal, None), Ok(15));
        assert_eq!(root.linux.vfs.pread(seal, 7, 0).unwrap(), b"payload");
        assert_eq!(k.parallel_rounds, 1);
        assert!(k.cohort_return_syscalls.is_empty());
        assert_eq!(k.service_requests, 0);
        assert_eq!(k.vm_checkpoint_groups, 0);
    }
}
