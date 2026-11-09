// SPDX-License-Identifier: GPL-3.0-or-later
use super::tests::{kernel, process};
use super::*;
use trames_cpu::Cpu;
use trames_engine::Cpu as _;
use trames_memory::{Permissions, PAGE_SIZE};

fn code(p: &mut Process<Cpu>, address: u64, words: &[u32]) {
    p.memory
        .write(
            address,
            &words
                .iter()
                .copied()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    p.memory
        .protect(address, PAGE_SIZE, Permissions::RX)
        .unwrap();
}

#[test]
fn source_poweroff_finishes_original_root_and_caller_groups_without_joined_execution() {
    for (cpus, slots) in [(4, 4), (12, 12), (4, 1)] {
        for caller in 1..=4 {
            for command in [0xcdef_0123, 0x4321_fedc] {
                let mut k = kernel();
                k.cpu_count = cpus;
                k.workers = crate::workers::Pool::new(slots);
                k.per_cpu = vec![Duration::ZERO; cpus];
                k.profile_syscalls = true;
                let mut root = process();
                k.install_proc_source(&root, None);
                let mut output = trames_linux::CapturedOutput::default();
                k.syscall(1, &mut root, 220, [0x10b00, 0, 0, 0, 0, 0], &mut output)
                    .unwrap();
                k.syscall(1, &mut root, 220, [17, 0, 0, 0, 0, 0], &mut output)
                    .unwrap();
                let mut child = k.processes.checkout(&3).unwrap();
                k.syscall(3, &mut child, 220, [0x10b00, 0, 0, 0, 0, 0], &mut output)
                    .unwrap();
                k.processes.insert(3, child);
                k.processes.insert(1, root);
                for id in 1..=4 {
                    let p = &mut *k.processes.get_mut(&id).unwrap();
                    // All four tasks start with pure computation. Only the
                    // selected caller enters the separately mapped power code.
                    p.memory
                        .protect(0x4000, PAGE_SIZE, Permissions::RW)
                        .unwrap();
                    code(p, 0x4000, &[0x14000000]);
                    p.cpu.set_pc(0x4000);
                    p.signals.io.scheduling.set_affinity((1 << slots) - 1);
                }
                {
                    let p = &mut *k.processes.get_mut(&caller).unwrap();
                    code(p, 0x5000, &[0xd4000001, 0xd28009a0, 0xd2800bc8, 0xd4000001]);
                    p.cpu.set_pc(0x5000);
                    for (i, value) in [0xfee1_dead, 0x2812_1969, command, u64::MAX, 0, 0]
                        .into_iter()
                        .enumerate()
                    {
                        p.cpu.set_x(i, value);
                    }
                    p.cpu.set_x(8, 142);
                }
                let root_group = k.processes.read(&1).signals.io.lifecycle().clone();
                let caller_group = k.processes.read(&caller).signals.io.lifecycle().clone();
                let exit = k.drive(&mut output, 10_000_000).unwrap();
                assert_eq!(exit.code, 0, "cpus={cpus} slots={slots} caller={caller}");
                assert_eq!(root_group.exit_status(), Some(0));
                assert_eq!(caller_group.termination(), Some(0));
                assert_eq!(k.parallel_rounds, 1);
                assert!(
                    k.cohort_return_syscalls.is_empty(),
                    "{:?}",
                    k.cohort_return_syscalls
                );
                assert_eq!(k.service_requests, 0);
                assert_eq!(k.serviced_syscalls, 0);
            }
        }
    }
}

#[test]
fn accepted_root_power_route_cannot_target_a_replacement_pid_or_task_body() {
    let mut k = kernel();
    let root = process();
    k.publish_task(1, &root);
    let original = root.signals.io.lifecycle().clone();
    let route = k.guest_shutdown.get().unwrap().clone();
    let replacement = process();
    let other = replacement.signals.io.lifecycle().clone();
    k.publish_task(1, &replacement);
    k.processes.insert(1, replacement);
    drop(root);
    assert!(Arc::ptr_eq(&route, k.guest_shutdown.get().unwrap()));
    route();
    assert_eq!(original.termination(), Some(0));
    assert_eq!(other.termination(), None);
}

#[test]
fn source_power_errors_precede_missing_capabilities_and_never_request_exit() {
    for nested in [false, true] {
        let mut k = kernel();
        let mut p = process();
        if nested {
            p.linux.vfs.unshare_pid().unwrap();
            p.linux.vfs.activate_child_pid(1).unwrap();
        }
        k.publish_task(1, &p);
        let group = p.signals.io.lifecycle().clone();
        k.processes.insert(1, p);
        let mut files = trames_vfs::FileEpoch::default();
        let mut rings = trames_linux::UringEpoch::default();
        let mut network = trames_vfs::NetworkEpoch::default();
        let mut job = dispatch::Dispatch::capture(&k).job(
            (1, k.processes.directory().handle(&1).unwrap()),
            None,
            &Arc::new(crate::workers::Control::new(100)),
            &mut files,
            &mut rings,
            &mut network,
        );
        let snapshot = job.work.syscalls.as_mut().unwrap();
        snapshot.direct = trames_linux::DirectSyscalls::default();
        assert_eq!(snapshot.shutdown_guest([0; 6], true), Some(Err(Errno(22))));
        let halt = [0xfee1_dead, 0x2812_1969, 0xcdef_0123, 0, 0, 0];
        assert_eq!(
            snapshot.shutdown_guest(halt, true),
            if nested { Some(Err(Errno(95))) } else { None }
        );
        assert_eq!(group.termination(), None);
        assert_eq!(
            snapshot.shutdown_guest(halt, false),
            if nested { Some(Err(Errno(95))) } else { None }
        );
        assert_eq!(group.termination(), None);
        snapshot
            .io_signals
            .credentials()
            .publish(&trames_vfs::Credentials::user(1000, 1000));
        assert_eq!(snapshot.shutdown_guest([0; 6], true), Some(Err(Errno(1))));
        assert_eq!(snapshot.shutdown_guest(halt, true), Some(Err(Errno(1))));
        assert_eq!(group.termination(), None);
    }
}
