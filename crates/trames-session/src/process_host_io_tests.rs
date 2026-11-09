// SPDX-License-Identifier: GPL-3.0-or-later
use super::tests::{kernel, process};
use super::*;
use trames_memory::{Permissions, PAGE_SIZE};

#[test]
fn native_backend_failure_drains_source_read_poll_and_uring_without_owner_replay() {
    for slots in [1, 4] {
        for mode in 0..7 {
            let mut k = kernel();
            let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
            let mut root = process();
            root.linux
                .vfs
                .configure_network(trames_vfs::NetworkMode::Loopback)
                .unwrap();
            let fd = root.linux.vfs.socket(2, 1, 0).unwrap();
            let socket = root.linux.vfs.socket_fd(fd).unwrap();
            assert!(matches!(
                socket.connect(listener.local_addr().unwrap()),
                Ok(()) | Err(trames_net::NetError(115))
            ));
            let (mut peer, _) = listener.accept().unwrap();
            assert_eq!(socket.connect_complete(), Ok(true));
            drop(socket);
            root.memory.write(0x1000, &[0xa5; 256]).unwrap();
            let mut args = [fd as u64, 0x1000, 1, 0, 0, 0];
            let number;
            let mut ring = None;
            match mode {
                0 | 5 => number = if mode == 0 { 63 } else { 207 },
                1 => {
                    let epoll = root.linux.vfs.epoll_create(0).unwrap();
                    root.linux.vfs.epoll_ctl(epoll, 1, fd, 1, 41).unwrap();
                    number = 22;
                    args = [epoll as u64, 0x1000, 1, u64::MAX, 0, 0];
                }
                2 => {
                    root.memory.write_array(0x2000, fd.to_le_bytes()).unwrap();
                    root.memory.write_array(0x2004, 1u16.to_le_bytes()).unwrap();
                    number = 73;
                    args = [0x2000, 1, 0, 0, 0, 0];
                }
                6 => {
                    let [_, writer] = root.linux.vfs.pipe(0).unwrap();
                    number = 76;
                    args = [fd as u64, 0, writer as u64, 0, 1, 0];
                }
                _ => {
                    let (ring_fd, original) = root.linux.vfs.uring_create(4, 8).unwrap();
                    for (address, offset, len) in [
                        (0x10000, 0, original.ring_bytes),
                        (0x20000, 0x10000000, original.sqe_bytes),
                    ] {
                        root.memory
                            .map_backed(
                                address,
                                root.linux
                                    .vfs
                                    .mapping_pages(ring_fd, offset, len, true, true)
                                    .unwrap(),
                                true,
                                Permissions::RW,
                                false,
                            )
                            .unwrap();
                    }
                    let mut sqe = [0u8; 64];
                    sqe[0] = 22;
                    sqe[4..8].copy_from_slice(&fd.to_le_bytes());
                    sqe[16..24].copy_from_slice(&0x1000u64.to_le_bytes());
                    sqe[24..28].copy_from_slice(&1u32.to_le_bytes());
                    sqe[32..40].copy_from_slice(&77u64.to_le_bytes());
                    root.memory.write(0x20000, &sqe).unwrap();
                    root.memory
                        .write_array(0x10004, 1u32.to_le_bytes())
                        .unwrap();
                    if mode == 4 {
                        assert_eq!(
                            k.syscall(
                                1,
                                &mut root,
                                426,
                                [ring_fd as u64, 1, 0, 0, 0, 0],
                                &mut trames_linux::CapturedOutput::default()
                            ),
                            Ok(Some(1))
                        );
                        number = 124;
                        args = [0x7788, 0, 0, 0, 0, 0];
                    } else {
                        number = 426;
                        args = [ring_fd as u64, 1, 1, 1, 0, 0];
                    }
                    ring = Some(original);
                }
            }
            for (i, value) in args.into_iter().enumerate() {
                root.cpu.set_x(i, value);
            }
            root.cpu.set_x(8, number);
            // A marker following SVC proves a host failure cannot return a
            // fabricated guest result and continue execution.
            root.memory
                .write(
                    0x4000,
                    &[0xd4000001u32, 0xd2800ef3, 0x14000000]
                        .into_iter()
                        .flat_map(u32::to_le_bytes)
                        .collect::<Vec<_>>(),
                )
                .unwrap();
            root.memory
                .protect(0x4000, PAGE_SIZE, Permissions::RX)
                .unwrap();
            k.cpu_count = slots;
            k.workers = crate::workers::Pool::new(slots);
            k.per_cpu = vec![Duration::ZERO; slots];
            k.profile_syscalls = true;
            k.processes.insert(1, root);
            for id in 2..=slots {
                let mut task = process();
                task.tgid = id as u32;
                task.memory
                    .write_array(0x4000, 0x14000000u32.to_le_bytes())
                    .unwrap();
                task.memory
                    .protect(0x4000, PAGE_SIZE, Permissions::RX)
                    .unwrap();
                k.processes.insert(id as u32, task);
            }
            k.publish_io_tasks(None);
            let members: Vec<_> = (1..=slots).map(|id| (id as u32, id - 1)).collect();
            let views = k.prepare_parallel_views(&members).unwrap();
            let control = Arc::new(crate::workers::Control::new(1_000_000_000));
            let epoch =
                crate::run_queue::Epoch::with_events(control.clone(), k.workers.events(), true);
            epoch.reject_host_events(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected original native event failure",
            ));
            epoch.bind_lifecycle(lifecycle::Lifecycle::capture(&k));
            let mut file_epoch = trames_vfs::FileEpoch::default();
            let mut uring_epoch = trames_linux::UringEpoch::default();
            let mut network_epoch = trames_vfs::NetworkEpoch::default();
            for (id, _, view) in views {
                epoch.add(k.capture_worker(
                    id,
                    view,
                    &control,
                    &mut file_epoch,
                    &mut uring_epoch,
                    &mut network_epoch,
                ));
            }
            epoch.assign(&members);
            for slot in 0..slots {
                k.workers.ensure(slot).unwrap();
                k.workers.launch(slot, epoch.clone()).unwrap();
            }
            let mut stopped = 0;
            while stopped < slots {
                match k.workers.event_timeout(Duration::from_secs(5)).unwrap() {
                    Some(crate::workers::Event::EpochStopped(_)) => stopped += 1,
                    _ => panic!("host error must stop actors without owner work: mode={mode}"),
                }
            }
            let error = epoch.collect_lifecycle(&mut k).unwrap();
            assert!(
                matches!(&error, RuntimeError::HostIo(error) if error.kind()==std::io::ErrorKind::PermissionDenied && error.to_string().contains("original native event failure"))
            );
            let done = epoch.drain();
            file_epoch.finish();
            let _ = uring_epoch.finish();
            let original = done.iter().find(|done| done.pid == 1).unwrap();
            assert_eq!(original.cpu.x(0), args[0]);
            assert_eq!(original.cpu.x(19), 0);
            assert_eq!(original.syscalls, 0);
            assert!(done
                .iter()
                .all(|done| done.serviced_syscalls == 0 && done.service_waits == 0));
            k.cancel_host_io_requests();
            let mut root = k.processes.get_mut(&1).unwrap();
            root.memory.commit_parallel().unwrap();
            assert_eq!(root.memory.read_array::<256>(0x1000).unwrap(), [0xa5; 256]);
            assert!(!root.linux.uring_requires_owner());
            if let Some(ring) = ring {
                assert!(ring.state.lock().unwrap().pending.is_empty());
                assert_eq!(ring.cq_ready(), 1);
                assert_eq!(
                    ring.read_queue::<8>(trames_vfs::URING_CQES),
                    77u64.to_le_bytes()
                );
                assert_eq!(
                    ring.read_queue::<4>(trames_vfs::URING_CQES + 8),
                    (-125i32).to_le_bytes()
                );
            }
            drop(network_epoch);
            root.linux.vfs.close(fd).unwrap();
            // A retained failed read must not postpone last transport close.
            use std::io::Read;
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
    }
}
