// SPDX-License-Identifier: GPL-3.0-or-later
//! Connected maintenance paths, using live original interests after acceptance.
use super::*;
use crate::uring::tests::{add, cq, setup, sqe};

struct Target;
impl IoWake for Target {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn caller(l: &Linux, m: &trames_memory::Memory) -> DirectSyscalls {
    DirectSyscalls::new(l.vfs.direct_descriptors())
        .with_paths(l.vfs.path_queries())
        .with_resources(l.vfs.descriptor_factory())
        .with_urings(
            UringEpoch::default()
                .capture(&l.vfs, m.instruction_identity().0, 7)
                .with_actor(l.uring_actor_root()),
        )
}
fn blocked(attempt: IoAttempt) -> PendingIo {
    match attempt {
        IoAttempt::Blocked(wait) => wait,
        IoAttempt::HostError(error) => panic!("host error: {error}"),
        _ => panic!("original wait must remain blocked"),
    }
}
fn complete(attempt: IoAttempt, n: u64) {
    match attempt {
        IoAttempt::Complete(result) => assert_eq!(result, Ok(n)),
        IoAttempt::Blocked(_) => panic!("still blocked"),
        IoAttempt::Checkpoint => panic!("unexpected execution checkpoint"),
        IoAttempt::WaitCheckpoint(_) => panic!("unexpected wait checkpoint"),
        IoAttempt::HostError(error) => panic!("host error: {error}"),
        _ => panic!("unexpected attempt"),
    }
}

#[test]
fn nested_interest_changes_refresh_background_enter_and_cq_waits_after_numeric_reuse() {
    // All four front doors share the same retained SQE and source graph.
    for mode in 0..4 {
        for cancel in [false, true] {
            let (mut l, mut m, fd, ring) = setup(8);
            let child = l.vfs.epoll_create(0).unwrap();
            let root = l.vfs.epoll_create(0).unwrap();
            let leaf = l.vfs.eventfd(0, 0).unwrap();
            l.vfs.epoll_ctl(root, 1, child, 1, 101).unwrap();
            let cq_epoll = l.vfs.epoll_create(0).unwrap();
            l.vfs.epoll_ctl(cq_epoll, 1, fd, 1, 102).unwrap();
            let d = caller(&l, &m);
            let target: Arc<dyn IoWake> = Arc::new(Target);
            let wake = Arc::downgrade(&target);
            let mut entry = sqe(6, root, 99);
            entry[28..32].copy_from_slice(&1u32.to_le_bytes());
            add(&mut m, &ring, entry);
            let accepted = d
                .start(
                    426,
                    [
                        fd as u64,
                        1,
                        u64::from(mode == 1),
                        u64::from(mode == 1),
                        0,
                        0,
                    ],
                    &mut m,
                    7,
                    &wake,
                    None,
                )
                .unwrap();
            let mut pending = if mode == 1 {
                Some(blocked(accepted))
            } else {
                complete(accepted, 1);
                None
            };
            let mut background = if mode == 0 {
                let mut wait = d.uring_background(7, &wake).unwrap();
                assert!(wait.progress(&mut m).unwrap());
                Some(wait)
            } else {
                None
            };
            if mode == 2 {
                let mut poll = [0u8; 8];
                poll[..4].copy_from_slice(&fd.to_le_bytes());
                poll[4..6].copy_from_slice(&1u16.to_le_bytes());
                m.write(0x2600, &poll).unwrap();
                pending = Some(blocked(
                    d.start(73, [0x2600, 1, 0, 0, 0, 0], &mut m, 7, &wake, None)
                        .unwrap(),
                ));
            } else if mode == 3 {
                pending = Some(blocked(
                    d.start(
                        22,
                        [cq_epoll as u64, 0x2600, 1, u32::MAX as u64, 0, 0],
                        &mut m,
                        7,
                        &wake,
                        None,
                    )
                    .unwrap(),
                ));
            }
            let signal = background
                .as_ref()
                .map(|wait| wait.signal.clone())
                .unwrap_or_else(|| pending.as_ref().unwrap().signal.clone());
            l.vfs.close(root).unwrap();
            assert_eq!(l.vfs.eventfd(0, 0).unwrap(), root);
            // ADD wakes the old parent, but its new leaf is not ready yet. A
            // deciding retry must subscribe that leaf before parking again.
            l.vfs.epoll_ctl(child, 1, leaf, 1, 103).unwrap();
            assert!(signal.ready(), "interest change failed to wake mode {mode}");
            if let Some(wait) = &mut background {
                assert!(wait.progress(&mut m).unwrap());
            } else {
                pending = Some(blocked(d.resume(pending.take().unwrap(), &mut m)));
            }
            signal.reset();
            if cancel {
                let other = DirectSyscalls::new(l.vfs.direct_descriptors()).with_urings(
                    UringEpoch::default()
                        .capture(&l.vfs, m.instruction_identity().0, 8)
                        .with_actor(l.uring_actor_root()),
                );
                let mut cancellation = sqe(14, 0, 100);
                cancellation[16..24].copy_from_slice(&99u64.to_le_bytes());
                add(&mut m, &ring, cancellation);
                complete(
                    other
                        .start(426, [fd as u64, 1, 0, 0, 0, 0], &mut m, 8, &wake, None)
                        .unwrap(),
                    1,
                );
            } else {
                // Neither numeric reuse nor unrelated data can replace the
                // accepted original root; only the new real leaf completes it.
                l.vfs.write(root, &1u64.to_le_bytes()).unwrap();
                assert!(!signal.ready());
                l.vfs.write(leaf, &1u64.to_le_bytes()).unwrap();
            }
            assert!(signal.ready(), "new leaf/cancel failed to wake mode {mode}");
            if let Some(wait) = &mut background {
                assert!(wait.progress(&mut m).unwrap());
                assert!(!wait.active());
            } else {
                complete(d.resume(pending.take().unwrap(), &mut m), 1);
            }
            assert_eq!(cq(&mut m, &ring), (99, if cancel { -125 } else { 1 }));
            if cancel {
                assert_eq!(cq(&mut m, &ring), (100, 0));
            }
            // Completed/cancelled SQEs no longer own leaf listeners.
            signal.reset();
            l.vfs.write(leaf, &1u64.to_le_bytes()).unwrap();
            assert!(!signal.ready());
        }
    }
}

#[test]
fn compatibility_capture_retains_original_body_resources_without_a_later_owner_or_observer() {
    let (mut l, mut m, fd, ring) = setup(8);
    l.vfs.set_runtime_info(1, Default::default());
    exclude_proc_provider(&l);
    let original = l.vfs.open_at(-100, b"/proc/version", 0, 0).unwrap();
    // No paths/factory are supplied by the later DirectSyscalls builder.
    let d = DirectSyscalls::new(l.vfs.direct_descriptors()).with_urings(
        UringEpoch::default()
            .capture(&l.vfs, m.instruction_identity().0, 7)
            .with_actor(l.uring_actor_root()),
    );
    let mut entry = sqe(22, original, 201);
    entry[16..24].copy_from_slice(&0x2200u64.to_le_bytes());
    entry[24..28].copy_from_slice(&8u32.to_le_bytes());
    add(&mut m, &ring, entry);
    let target: Arc<dyn IoWake> = Arc::new(Target);
    complete(
        d.start(
            426,
            [fd as u64, 1, 1, 1, 0, 0],
            &mut m,
            7,
            &Arc::downgrade(&target),
            None,
        )
        .unwrap(),
        1,
    );
    assert_eq!(cq(&mut m, &ring), (201, 8));
    assert_eq!(m.read_array::<8>(0x2200).unwrap(), *b"Linux ve");
}

#[test]
fn retained_epoll_watching_its_request_ring_has_no_ownership_cycle() {
    let (mut l, mut m, fd, ring) = setup(8);
    let epoll = l.vfs.epoll_create(0).unwrap();
    l.vfs.epoll_ctl(epoll, 1, fd, 1, 1).unwrap();
    let weak = Arc::downgrade(&ring);
    let d = caller(&l, &m);
    let mut entry = sqe(6, epoll, 202);
    entry[28..32].copy_from_slice(&1u32.to_le_bytes());
    add(&mut m, &ring, entry);
    let target: Arc<dyn IoWake> = Arc::new(Target);
    complete(
        d.start(
            426,
            [fd as u64, 1, 0, 0, 0, 0],
            &mut m,
            7,
            &Arc::downgrade(&target),
            None,
        )
        .unwrap(),
        1,
    );
    assert_eq!(ring.state.lock().unwrap().pending.len(), 1);
    l.vfs.close(epoll).unwrap();
    l.vfs.close(fd).unwrap();
    drop((d, m, ring));
    assert!(weak.upgrade().is_none());
}

#[test]
fn cold_packet_binding_keeps_the_accepted_ofd_through_numeric_reuse() {
    let (mut linux, mut memory, _, _) = setup(8);
    let [fd, peer] = linux.vfs.socketpair(1, 5, 0).unwrap();
    memory.write(0x2200, b"original").unwrap();
    let args = [fd as u64, 0x2200, 8, 0, 0, 0];
    let direct = DirectSyscalls::new(linux.vfs.direct_descriptors());
    let target: Arc<dyn IoWake> = Arc::new(Target);
    let file = match direct
        .start_owned_byte(None, 64, args, &mut memory, 7, &Arc::downgrade(&target))
        .unwrap()
    {
        IoAttempt::ByteCheckpoint(file) => file,
        _ => panic!("a packet without its factory needs its original binding"),
    };
    linux.vfs.close(fd).unwrap();
    assert_eq!(linux.vfs.eventfd(23, 0).unwrap(), fd);
    complete(
        direct.start_original_byte(
            file,
            64,
            args,
            &mut linux,
            &mut memory,
            7,
            &Arc::downgrade(&target),
        ),
        8,
    );
    assert_eq!(linux.vfs.read(peer, 8).unwrap(), b"original");
    assert_eq!(linux.vfs.read(fd, 8).unwrap(), 23u64.to_le_bytes());
}

#[test]
fn cold_poll_and_select_bind_the_original_reader_without_fd_or_buffer_donation() {
    use std::sync::atomic::{AtomicBool, Ordering};
    #[derive(Default)]
    struct Reader {
        ready: AtomicBool,
        changed: Arc<trames_vfs::Readiness>,
    }
    impl trames_vfs::SignalReader for Reader {
        fn poll(&self, _: u64) -> (u16, [u64; 2]) {
            (u16::from(self.ready.load(Ordering::Relaxed)), [0; 2])
        }
        fn take(&self, _: u64) -> Option<[u8; 128]> {
            None
        }
        fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<trames_vfs::IoSubscription> {
            vec![self.changed.subscribe(signal)]
        }
    }
    for number in [72, 73] {
        let (mut linux, mut memory, _, _) = setup(8);
        let fd = linux.vfs.signalfd(-1, 1 << 9, 0).unwrap();
        let args = if number == 73 {
            let mut row = [0; 8];
            row[..4].copy_from_slice(&fd.to_le_bytes());
            row[4..6].copy_from_slice(&1u16.to_le_bytes());
            memory.write(0x2600, &row).unwrap();
            [0x2600, 1, 0, 0, 8, 0]
        } else {
            memory
                .write_array(0x2600, (1u64 << fd).to_le_bytes())
                .unwrap();
            [fd as u64 + 1, 0x2600, 0, 0, 0, 0]
        };
        let wait = Arc::new(
            crate::RetainedWait::prepare_joined(&linux.vfs, &memory, number, args, None)
                .unwrap()
                .unwrap(),
        );
        let direct = DirectSyscalls::default();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let wait = match direct.start_retained_poll(
            wait,
            args,
            &mut memory,
            7,
            &Arc::downgrade(&target),
            None,
        ) {
            IoAttempt::WaitCheckpoint(wait) => wait,
            _ => panic!("an accepted signal wait needs its original reader"),
        };
        let reader = Arc::<Reader>::default();
        linux.vfs.bind_signal_reader(reader.clone());
        linux.vfs.close(fd).unwrap();
        assert_eq!(linux.vfs.eventfd(17, 0).unwrap(), fd);
        memory.write_array(0x2600, u64::MAX.to_le_bytes()).unwrap();
        let pending = blocked(direct.start_original_poll(
            wait,
            &mut linux,
            &mut memory,
            7,
            &Arc::downgrade(&target),
        ));
        reader.ready.store(true, Ordering::Relaxed);
        reader.changed.notify_locked();
        assert!(pending.signal.ready());
        complete(direct.resume(pending, &mut memory), 1);
        if number == 73 {
            assert_eq!(memory.read_array::<2>(0x2606).unwrap(), 1u16.to_le_bytes());
        } else {
            assert_eq!(memory.read_u64(0x2600).unwrap(), 1u64 << fd);
        }
        assert_eq!(linux.vfs.read(fd, 8).unwrap(), 17u64.to_le_bytes());
    }
}

#[test]
fn bpf_poll_retains_canonical_never_ready_semantics_after_descriptor_reuse() {
    let (mut linux, mut memory, _, _) = setup(8);
    let code = [0xb7, 0, 0, 0, 1, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
    let fd = linux.vfs.bpf_load_program(15, &code).unwrap();
    assert_eq!(linux.vfs.poll(fd, 5), 0);
    let mut row = [0; 8];
    row[..4].copy_from_slice(&fd.to_le_bytes());
    row[4..6].copy_from_slice(&5u16.to_le_bytes());
    memory.write(0x2600, &row).unwrap();
    let direct = caller(&linux, &memory);
    let target: Arc<dyn IoWake> = Arc::new(Target);
    let pending = blocked(
        direct
            .start(
                73,
                [0x2600, 1, 0, 0, 8, 0],
                &mut memory,
                7,
                &Arc::downgrade(&target),
                None,
            )
            .unwrap(),
    );
    linux.vfs.close(fd).unwrap();
    assert_eq!(linux.vfs.eventfd(19, 0).unwrap(), fd);
    let _pending = blocked(direct.resume(pending, &mut memory));
    assert_eq!(linux.vfs.read(fd, 8).unwrap(), 19u64.to_le_bytes());
}

#[test]
fn an_accepted_opaque_sqe_without_a_fast_provider_completes_on_its_original_body() {
    let (mut linux, mut memory, ring_fd, ring) = setup(8);
    linux.vfs.mkdir_at(-100, b"/original", 0o755).unwrap();
    linux
        .vfs
        .import_file(b"/original/file", b"original".to_vec())
        .unwrap();
    let gate = linux.vfs.eventfd(0, 0).unwrap();
    let directory = linux
        .vfs
        .open_at(-100, b"/original", trames_vfs::O_DIRECTORY, 0)
        .unwrap();
    memory.write(0x2400, b"file\0").unwrap();
    let mut first = sqe(22, gate, 100);
    first[1] = 4;
    first[16..24].copy_from_slice(&0x2200u64.to_le_bytes());
    first[24..28].copy_from_slice(&8u32.to_le_bytes());
    add(&mut memory, &ring, first);
    let mut open = sqe(18, directory, 101);
    open[16..24].copy_from_slice(&0x2400u64.to_le_bytes());
    add(&mut memory, &ring, open);
    assert_eq!(
        linux.uring_enter([ring_fd as u64, 2, 0, 0, 0, 0], &mut memory, None, 7),
        Ok((2, true))
    );
    let lease = ring
        .state
        .lock()
        .unwrap()
        .pending
        .iter_mut()
        .find(|r| r.sqe.opcode() == 18)
        .unwrap()
        .execution
        .take();
    drop(lease);
    let bare = DirectSyscalls::new(linux.vfs.direct_descriptors()).with_urings(
        UringEpoch::default()
            .capture_worker(
                &linux.vfs,
                memory.instruction_identity().0,
                7,
                &Default::default(),
                &BTreeMap::new(),
            )
            .with_actor(linux.uring_actor_root()),
    );
    let target: Arc<dyn IoWake> = Arc::new(Target);
    let mut background = bare.uring_background(7, &Arc::downgrade(&target)).unwrap();
    assert!(background.progress(&mut memory).unwrap());
    assert!(!background.needs_progress());
    linux.vfs.close(directory).unwrap();
    assert_eq!(linux.vfs.eventfd(99, 0).unwrap(), directory);
    memory.write(0x2400, b"nope\0").unwrap();
    linux.vfs.write(gate, &17u64.to_le_bytes()).unwrap();
    assert!(background.signal.ready());
    assert!(
        !background.progress(&mut memory).unwrap(),
        "the unbound open needs its original body"
    );
    background
        .progress_original(&mut linux, &mut memory)
        .unwrap();
    assert!(!background.active());
    assert_eq!(cq(&mut memory, &ring), (100, 8));
    let (tag, fd) = cq(&mut memory, &ring);
    assert_eq!(tag, 101);
    assert!(fd >= 0);
    assert_eq!(linux.vfs.read(fd as u32, 8).unwrap(), b"original");
    assert_eq!(memory.read_u64(0x2200).unwrap(), 17);
    assert_eq!(linux.vfs.read(directory, 8).unwrap(), 99u64.to_le_bytes());
    assert!(background.progress(&mut memory).unwrap());
}

#[test]
fn original_poll_keeps_native_backend_failure_but_ready_results_win_stale_interests() {
    struct Failed;
    impl IoWake for Failed {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
        fn host_events(&self) -> std::io::Result<Option<Arc<trames_vfs::HostEvents>>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "original poll backend failure",
            ))
        }
    }
    struct Reader(bool);
    impl trames_vfs::SignalReader for Reader {
        fn poll(&self, _: u64) -> (u16, [u64; 2]) {
            (u16::from(self.0), [0; 2])
        }
        fn take(&self, _: u64) -> Option<[u8; 128]> {
            None
        }
        fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<trames_vfs::IoSubscription> {
            vec![trames_vfs::IoSubscription::native_direction(
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "original native interest failure",
                )),
                false,
                signal,
            )]
        }
    }
    for ready in [false, true] {
        let (mut linux, mut memory, _, _) = setup(8);
        let fd = linux.vfs.signalfd(-1, 1 << 9, 0).unwrap();
        let mut row = [0; 8];
        row[..4].copy_from_slice(&fd.to_le_bytes());
        row[4..6].copy_from_slice(&1u16.to_le_bytes());
        memory.write(0x2600, &row).unwrap();
        let args = [0x2600, 1, 0, 0, 8, 0];
        let wait = Arc::new(
            crate::RetainedWait::prepare_joined(&linux.vfs, &memory, 73, args, None)
                .unwrap()
                .unwrap(),
        );
        linux.vfs.bind_signal_reader(Arc::new(Reader(ready)));
        let target: Arc<dyn IoWake> = Arc::new(Failed);
        let result = DirectSyscalls::default().start_original_poll(
            wait,
            &mut linux,
            &mut memory,
            7,
            &Arc::downgrade(&target),
        );
        if ready {
            complete(result, 1);
        } else {
            assert!(
                matches!(result,IoAttempt::HostError(error) if error.kind()==std::io::ErrorKind::PermissionDenied)
            );
        }
    }
}
