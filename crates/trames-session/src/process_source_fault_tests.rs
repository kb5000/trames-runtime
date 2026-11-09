// SPDX-License-Identifier: GPL-3.0-or-later
use super::tests::{kernel, process};
use super::*;
use trames_memory::{Permissions, PAGE_SIZE};

fn words<C: Cpu>(p: &mut Process<C>, address: u64, code: &[u32]) {
    p.memory
        .write(
            address,
            &code
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    p.memory
        .protect(address, PAGE_SIZE, Permissions::RX)
        .unwrap();
}
fn wait() -> [u32; 7] {
    [
        0xd2860000, 0xd2801001, 0xd2800002, 0xd2800003, 0xd2800c48, 0xd4000001, 0x14000000,
    ]
}
fn peer(root: &Process<trames_cpu::Cpu>) -> Box<Process<trames_cpu::Cpu>> {
    let mut peer = root.fork();
    peer.vm_id = 2;
    peer.tgid = 2;
    peer.cpu.set_pc(0x6000);
    peer
}

#[test]
fn caught_cpu_and_rejected_native_faults_restore_the_original_frame_on_source() {
    for (cpus, slots, filtered) in [(4, 4, false), (12, 12, false), (4, 1, false), (4, 1, true)] {
        for alternate in [false, true] {
            for kind in 0..6 {
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
                let (mut code, signal, fault_code, fault_address) = match kind {
                    0 => (vec![0xd2920009, 0xf9400120], 11, 1, 0x9000),
                    1 => {
                        root.memory.map(0x9000, PAGE_SIZE, Permissions::R).unwrap();
                        (vec![0xd2920009, 0xf9000127], 11, 2, 0x9000)
                    }
                    2 => (vec![0xd4200000], 5, 1, 0x4000),
                    3 => (vec![0xffffffff], 4, 1, 0x4000),
                    4 => {
                        root.cpu.set_native_calls(true);
                        root.cpu.set_x(16, trames_accel::native::PROFILE);
                        root.cpu.set_x(17, 1);
                        (vec![trames_accel::native::INSTRUCTION], 4, 1, 0x4000)
                    }
                    _ => {
                        root.linux.vfs.import_file(b"/bus", vec![1]).unwrap();
                        let file = root.linux.vfs.open_at(-100, b"/bus", 0, 0).unwrap();
                        let pages = root
                            .linux
                            .vfs
                            .mapping_pages(file, PAGE_SIZE, PAGE_SIZE, true, false)
                            .unwrap();
                        root.memory
                            .map_backed(0xa000, pages, true, Permissions::R, false)
                            .unwrap();
                        (vec![0xd2940009, 0xf9400120], 7, 2, 0xa000)
                    }
                };
                root.cpu.set_x(7, 0x3377);
                root.signals.set_mask(1 << 12);
                root.signals.actions.set(
                    signal,
                    Action {
                        handler: 0x5000,
                        flags: 4 | 0x04000000 | if alternate { 0x08000000 } else { 0 },
                        restorer: 0x5080,
                        mask: 1 << 9,
                    },
                );
                if alternate {
                    root.signals.alt_stack = trames_kernel::signal::AltStack {
                        sp: 0x2000,
                        size: 0x2000,
                        flags: 0,
                    };
                }
                code.extend([0xd2850000, 0xd2800021, 0xb9000001]);
                code.extend(wait());
                words(&mut root, 0x4000, &code);
                words(
                    &mut root,
                    0x5000,
                    &[
                        0xd283000c, 0xb9000180, 0xb9400829, 0xb9000589, 0xf9400829, 0xf9000589,
                        0xf940dc4a, 0x9100114a, 0xf900dc4a, 0xd65f03c0,
                    ],
                );
                // Same executable page; do not call protect a second time.
                root.memory
                    .protect(0x5000, PAGE_SIZE, Permissions::RW)
                    .unwrap();
                root.memory
                    .write(0x5080, &[0x68, 0x11, 0x80, 0xd2, 1, 0, 0, 0xd4])
                    .unwrap();
                root.memory
                    .protect(0x5000, PAGE_SIZE, Permissions::RX)
                    .unwrap();
                words(&mut root, 0x6000, &wait());
                let other = peer(&root);
                k.processes.insert(1, root);
                k.processes.insert(2, other);
                assert!(k
                    .parallel_round(&mut trames_linux::CapturedOutput::default(), 1_000_000)
                    .unwrap());
                let root = k.processes.get_mut(&1).unwrap();
                eprintln!("source-fault CPUs={cpus} slots={slots} filter={filtered} alt={alternate} kind={kind} cohorts={} marker={:?} returned={:?}", k.parallel_rounds, root.memory.read_array::<4>(0x2800).unwrap(), k.cohort_return_syscalls);
                assert_eq!(
                    root.memory.read_array::<4>(0x2800).unwrap(),
                    1u32.to_le_bytes()
                );
                assert_eq!(
                    root.memory.read_array::<4>(0x1800).unwrap(),
                    (signal as u32).to_le_bytes()
                );
                assert_eq!(
                    root.memory.read_array::<4>(0x1804).unwrap(),
                    (fault_code as u32).to_le_bytes()
                );
                assert_eq!(root.memory.read_u64(0x1808).unwrap(), fault_address);
                assert_eq!(root.cpu.x(7), 0x3377);
                assert_eq!(root.cpu.sp, 0x9000);
                assert_eq!(root.signals.frames, 0);
                assert_eq!(root.signals.mask, 1 << 12);
                let log = root
                    .linux
                    .vfs
                    .kernel_log_capability()
                    .syslog(3, 8192)
                    .unwrap();
                assert!(String::from_utf8_lossy(&log).contains("pid=1 tgid=1"));
                assert_eq!(k.parallel_rounds, 1);
                assert!(k.cohort_return_syscalls.is_empty());
                assert!(k.cohort_return_native.is_empty());
                assert_eq!(k.service_requests, 0);
                assert_eq!(k.vm_checkpoint_groups, 0);
            }
        }
    }
}

#[test]
fn signal_frame_failures_and_bad_sigreturn_finish_on_source_without_stopping_peer() {
    for (cpus, slots) in [(4, 4), (12, 12), (4, 1)] {
        for kind in 0..5 {
            let mut k = kernel();
            k.cpu_count = cpus;
            k.workers = crate::workers::Pool::new(slots);
            k.per_cpu = vec![Duration::ZERO; cpus];
            k.profile_syscalls = true;
            let mut root = process();
            words(
                &mut root,
                0x6000,
                &[
                    0xd2850000, 0xd2800021, 0xb9000001, 0xd2860000, 0xd2801001, 0xd2800002,
                    0xd2800003, 0xd2800c48, 0xd4000001, 0x14000000,
                ],
            );
            let mut other = peer(&root);
            other.vm_id = 1;
            other.tgid = 1;
            root.vm_id = 2;
            root.tgid = 2;
            let code = if kind == 2 {
                vec![0xd2801168, 0xd4000001, 0x14000000]
            } else if kind == 3 {
                vec![0xffffffff]
            } else if kind == 4 {
                words(&mut root, 0x5000, &[0xf9400120]);
                vec![0xd2920009, 0xf9400120]
            } else {
                // Raise on this original thread after live source admission.
                vec![0xd2800040, 0xd2800141, 0xd2801048, 0xd4000001, 0x14000000]
            };
            words(&mut root, 0x4000, &code);
            if kind == 1 {
                root.signals.frames = 8;
            } else if kind != 4 {
                root.cpu.sp = 0;
            }
            if kind != 2 {
                root.signals.actions.set(
                    if kind == 3 {
                        4
                    } else if kind == 4 {
                        11
                    } else {
                        10
                    },
                    Action {
                        handler: 0x5000,
                        ..Default::default()
                    },
                );
            }
            let group = root.signals.io.lifecycle().clone();
            k.processes.insert(2, root);
            k.processes.insert(1, other);
            assert!(k
                .parallel_round(&mut trames_linux::CapturedOutput::default(), 1_000_000)
                .unwrap());
            assert_eq!(group.exit_status(), Some(11));
            assert_eq!(
                k.processes
                    .get_mut(&1)
                    .unwrap()
                    .memory
                    .read_array::<4>(0x2800)
                    .unwrap(),
                1u32.to_le_bytes()
            );
            assert_eq!(k.parallel_rounds, 1);
            assert!(k.cohort_return_syscalls.is_empty());
            assert_eq!(k.service_requests, 0);
        }
    }
}
