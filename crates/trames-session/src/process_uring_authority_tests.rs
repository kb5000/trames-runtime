// SPDX-License-Identifier: GPL-3.0-or-later
use super::tests::{kernel, process};
use super::*;
use trames_memory::{Permissions, PAGE_SIZE};

#[test]
fn solo_signal_request_keeps_original_task_authority_while_guest_waits_in_a_live_cohort() {
    for (cpus, slots) in [(4, 4), (12, 12), (4, 1)] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; cpus];
        k.profile_syscalls = true;
        let mut root = process();
        root.signals.set_mask(1 << 9);
        root.bind_signals();
        let signal = root.linux.vfs.signalfd(-1, 1 << 9, 0).unwrap();
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
        root.memory.write(0x1000, &[0xa5; 128]).unwrap();
        let mut sqe = [0; 64];
        sqe[0] = 22;
        sqe[4..8].copy_from_slice(&signal.to_le_bytes());
        sqe[16..24].copy_from_slice(&0x1000u64.to_le_bytes());
        sqe[24..28].copy_from_slice(&128u32.to_le_bytes());
        sqe[32..40].copy_from_slice(&131u64.to_le_bytes());
        root.memory.write(0x20000, &sqe).unwrap();
        root.memory
            .write_array(0x10004, 1u32.to_le_bytes())
            .unwrap();
        assert_eq!(
            k.syscall(
                1,
                &mut root,
                426,
                [fd as u64, 1, 0, 0, 0, 0],
                &mut trames_linux::CapturedOutput::default()
            ),
            Ok(Some(1))
        );
        assert_eq!(ring.state.lock().unwrap().pending.len(), 1);
        root.linux.vfs.close(signal).unwrap();
        assert_eq!(root.linux.vfs.eventfd(93, 0).unwrap(), signal);
        // The original CPU waits indefinitely while its async source request
        // runs. The peer sends a real private signal, then parks as well.
        let wait = [
            0xd2860000u32,
            0xd2801001,
            0xd2800002,
            0xd2800003,
            0xd2800c48,
            0xd4000001,
            0x14000000,
        ];
        root.memory
            .write(
                0x4000,
                &wait
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let mut send = vec![
            0xd2800020u32,
            0xd2800021,
            0xd2800142,
            0xd2801068,
            0xd4000001,
            0xaa0003f3,
        ];
        send.extend(wait);
        root.memory
            .write(
                0x5000,
                &send
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        root.memory
            .protect(0x4000, 2 * PAGE_SIZE, Permissions::RX)
            .unwrap();
        root.signals.io.scheduling.set_affinity((1 << slots) - 1);
        let mut peer = process();
        peer.signals.io_directory = root.signals.io_directory.clone();
        peer.tgid = 2;
        peer.vm_id = root.vm_id;
        peer.memory = root.memory.share();
        peer.linux.vfs = root.linux.vfs.clone_with_resources(true, false);
        peer.signals.set_mask(1 << 9);
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
        assert_eq!(k.parallel_rounds, 1);
        assert_eq!(k.service_requests, 0);
        assert_eq!(k.vm_checkpoint_groups, 0);
        assert!(
            k.cohort_return_syscalls.is_empty(),
            "{:?}",
            k.cohort_return_syscalls
        );
        assert_eq!(k.processes.read(&2).cpu.x(19), 0);
        assert_eq!(ring.cq_ready(), 1);
        assert_eq!(
            ring.read_queue::<8>(trames_vfs::URING_CQES),
            131u64.to_le_bytes()
        );
        assert_eq!(
            ring.read_queue::<4>(trames_vfs::URING_CQES + 8),
            128u32.to_le_bytes()
        );
        let mut root = k.processes.get_mut(&1).unwrap();
        assert!(matches!(root.state, State::Futex { .. }));
        assert_eq!(
            root.memory.read_array::<4>(0x1000).unwrap(),
            10u32.to_le_bytes()
        );
        assert_eq!(
            root.memory.read_array::<4>(0x100c).unwrap(),
            2u32.to_le_bytes()
        );
        assert!(!root.linux.uring_requires_owner());
        assert_eq!(root.linux.vfs.read(signal, 8).unwrap(), 93u64.to_le_bytes());
    }
}
