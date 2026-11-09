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
            assert!(!l.uring_requires_owner());
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
    assert!(!l.uring_requires_owner());
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
