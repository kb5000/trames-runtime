// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};
use trames_vfs::Vfs;

struct Target;
impl IoWake for Target {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn target() -> Arc<dyn IoWake> {
    Arc::new(Target)
}
fn blocked(attempt: IoAttempt) -> PendingIo {
    let IoAttempt::Blocked(wait) = attempt else {
        panic!("original event operation must release its slot");
    };
    assert_eq!(wait.interruptible_file_wait(), Some(false));
    assert_eq!(wait.wake_deadline(), None);
    wait
}

#[test]
fn caller_poll_provider_observes_the_accepted_stdin_after_its_numeric_fd_is_reused() {
    let mut v = Vfs::default();
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.write_array(0x10000, 0u32.to_le_bytes()).unwrap();
    memory.write_array(0x10004, 1u16.to_le_bytes()).unwrap();
    memory.write_array(0x10020, [0u8; 16]).unwrap();
    let wait =
        crate::RetainedWait::prepare_joined(&v, &memory, 73, [0x10000, 1, 0x10020, 0, 0, 0], None)
            .unwrap()
            .unwrap();
    v.close(0).unwrap();
    assert_eq!(v.eventfd(0, 0).unwrap(), 0);
    let mut observations = 0;
    assert_eq!(
        wait.check_owned(&mut memory, &v, 0, |kind, events| {
            assert_eq!(*kind, trames_vfs::FdKind::Stdin);
            observations += 1;
            Ok(Some((events & 1, [0; 2])))
        }),
        Ok(1)
    );
    assert_eq!(observations, 1);
    assert_eq!(memory.read_array::<2>(0x10006).unwrap(), 1u16.to_le_bytes());
}

#[test]
fn caller_epoll_handoff_retains_nested_provider_and_the_accepted_event_across_output_faults() {
    let mut v = Vfs::default();
    let child = v.epoll_create(0).unwrap();
    let parent = v.epoll_create(0).unwrap();
    v.epoll_ctl(child, 1, 0, 1 | 0x4000_0000, 17).unwrap();
    v.epoll_ctl(parent, 1, child, 1 | 0x4000_0000, 23).unwrap();
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x11000);
    let wait = crate::RetainedWait::prepare_joined(
        &v,
        &memory,
        22,
        [parent as u64, 0x10ff4, 1, 0, 0, 0],
        None,
    )
    .unwrap()
    .unwrap();
    assert_eq!(wait.check(&mut memory), Err(Errno(95)));
    assert!(wait.needs_owner());
    let mut observations = 0;
    assert_eq!(
        wait.check_owned(&mut memory, &v, 0, |kind, events| {
            if *kind == trames_vfs::FdKind::Stdin {
                observations += 1;
                Ok(Some((events & 1, [0; 2])))
            } else {
                Ok(None)
            }
        }),
        Err(Errno(14))
    );
    assert!(wait.take_fault().is_some());
    assert!(!wait.needs_owner());
    assert_eq!(observations, 1);
    v.close(parent).unwrap();
    assert_eq!(v.eventfd(0, 0).unwrap(), parent);
    page.finish();
    assert_eq!(
        wait.check_owned(&mut memory, &v, 0, |_, _| panic!(
            "accepted readiness must not be queried twice"
        )),
        Ok(1)
    );
    assert_eq!(
        memory.read_array::<8>(0x10ffc).unwrap(),
        23u64.to_le_bytes()
    );
    assert_eq!(
        v.epoll_wait_signals(child, 1, 0, |kind, events| {
            Ok((*kind == trames_vfs::FdKind::Stdin).then_some((events & 1, [0; 2])))
        })
        .unwrap(),
        vec![(1, 17)],
        "observing the child must leave its oneshot armed"
    );
}

#[test]
fn epoll_failed_event_copy_commits_only_full_records_and_preserves_padding_and_uncopied_oneshots() {
    let target = target();
    for prior in [0u64, 1] {
        let mut v = Vfs::default();
        let epoll = v.epoll_create(0).unwrap();
        for i in 0..=prior {
            let event = v.eventfd(1, 0).unwrap();
            v.epoll_ctl(epoll, 1, event, 1 | 0x4000_0000, 101 + i)
                .unwrap();
        }
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let mut memory = Memory::default();
        memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
        let address = 0x10ff4 - prior * 16;
        for i in 0..=prior {
            memory.write(address + i * 16 + 4, b"KEEP").unwrap();
        }
        let args = [epoll as u64, address, prior + 1, 0, 0, 0];
        let attempt = direct
            .start(22, args, &mut memory, 1, &Arc::downgrade(&target), None)
            .unwrap();
        if prior == 0 {
            assert!(matches!(attempt, IoAttempt::Complete(Err(Errno(14)))));
        } else {
            assert!(matches!(attempt, IoAttempt::Complete(Ok(1))));
        }
        for i in 0..=prior {
            assert_eq!(
                memory.read_array::<4>(address + i * 16 + 4).unwrap(),
                *b"KEEP"
            );
        }
        assert_eq!(
            v.epoll_wait(epoll, 4, |_, _| Ok(None)).unwrap(),
            vec![(1, 101 + prior)],
            "only fully copied events consume their oneshot"
        );
        assert_eq!(direct.completed.get(), 1);
    }
}

#[test]
fn cancelling_epoll_copy_keeps_uncopied_events_and_releases_its_original_mutex() {
    let target = target();
    for prior in [0u64, 1] {
        let mut v = Vfs::default();
        let epoll = v.epoll_create(0).unwrap();
        for i in 0..=prior {
            let event = v.eventfd(1, 0).unwrap();
            v.epoll_ctl(epoll, 1, event, 1 | 0x4000_0000, 101 + i)
                .unwrap();
        }
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let mut memory = Memory::default();
        memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
        let _page = file::copyout_tests::install(&mut memory, 0x11000);
        let args = [epoll as u64, 0x10ff4 - prior * 16, prior + 1, 0, 0, 0];
        let wait = blocked(
            direct
                .start(22, args, &mut memory, 1, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        assert_eq!(v.epoll_wait(epoll, 4, |_, _| Ok(None)), Err(Errno(11)));
        drop(wait);
        assert_eq!(
            v.epoll_wait(epoll, 4, |_, _| Ok(None)).unwrap(),
            vec![(1, 101 + prior)]
        );
    }
}

#[test]
fn epoll_control_waits_for_the_original_copy_and_keeps_both_ofds_and_parameters_across_reuse() {
    let target = target();
    let mut v = Vfs::default();
    let event = v.eventfd(1, 0).unwrap();
    let _event_duplicate = v.dup(event, 0, false).unwrap();
    let epoll = v.epoll_create(0).unwrap();
    let duplicate = v.dup(epoll, 0, false).unwrap();
    v.epoll_ctl(epoll, 1, event, 1 | 0x4000_0000, 55).unwrap();
    let direct = DirectSyscalls::new(v.direct_descriptors()).with_membership(v.shared_files());
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x11000);
    let wait = blocked(
        direct
            .start(
                22,
                [epoll as u64, 0x10ffe, 1, 0, 0, 0],
                &mut memory,
                1,
                &Arc::downgrade(&target),
                None,
            )
            .unwrap(),
    );
    memory.write_array(0x10020, 1u32.to_le_bytes()).unwrap();
    memory.write_array(0x10028, 88u64.to_le_bytes()).unwrap();
    let args = [epoll as u64, 3, event as u64, 0x10020, 0, 0];
    assert_eq!(direct.invoke_epoll_control(21, args, &memory), None);
    let control = blocked(
        direct
            .start_file_call(21, args, &mut memory, 2, &Arc::downgrade(&target))
            .unwrap(),
    );
    assert!(!control.signal.ready());
    v.shared_files().close_range(event, event, 0, 1).unwrap();
    assert_eq!(v.eventfd(9, 0).unwrap(), event);
    v.shared_files().close_range(epoll, epoll, 0, 1).unwrap();
    assert_eq!(v.epoll_create(0).unwrap(), epoll);
    memory.write_array(0x10020, 4u32.to_le_bytes()).unwrap();
    memory.write_array(0x10028, 99u64.to_le_bytes()).unwrap();
    page.finish();
    assert!(matches!(
        direct.resume(wait, &mut memory),
        IoAttempt::Complete(Ok(1))
    ));
    assert_eq!(
        memory.read_array::<8>(0x11006).unwrap(),
        55u64.to_le_bytes()
    );
    assert!(
        control.signal.ready(),
        "original epoll release wakes ctl without a timer"
    );
    assert!(matches!(
        direct.resume(control, &mut memory),
        IoAttempt::Complete(Ok(0))
    ));
    assert_eq!(
        v.epoll_wait(duplicate, 1, |_, _| Ok(None)).unwrap(),
        vec![(1, 88)]
    );
    assert!(v.epoll_wait(epoll, 1, |_, _| Ok(None)).unwrap().is_empty());
    assert_eq!(direct.fd_control_completed(), 1);
}

#[test]
fn zero_timeout_poll_and_select_wait_for_a_busy_nested_epoll_before_sampling_readiness() {
    let target = target();
    for number in [73, 72] {
        let mut v = Vfs::default();
        let event = v.eventfd(1, 0).unwrap();
        let child = v.epoll_create(0).unwrap();
        let parent = v.epoll_create(0).unwrap();
        v.epoll_ctl(child, 1, event, 1 | 0x4000_0000, 55).unwrap();
        v.epoll_ctl(parent, 1, child, 1, 66).unwrap();
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let mut memory = Memory::default();
        memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
        let page = file::copyout_tests::install(&mut memory, 0x11000);
        let copy = blocked(
            direct
                .start(
                    22,
                    [child as u64, 0x10ffe, 1, 0, 0, 0],
                    &mut memory,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        memory.write_array(0x10000, [0u8; 16]).unwrap();
        let args = if number == 73 {
            memory
                .write_array(0x10020, (parent as u64 | (1u64 << 32)).to_le_bytes())
                .unwrap();
            [0x10020, 1, 0x10000, 0, 0, 0]
        } else {
            memory
                .write_array(0x10020, (1u64 << parent).to_le_bytes())
                .unwrap();
            [(parent + 1) as u64, 0x10020, 0, 0, 0x10000, 0]
        };
        let poll = blocked(
            direct
                .start(number, args, &mut memory, 2, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        assert!(
            !poll.signal.ready(),
            "an expired timeout cannot spin on a held epoll mutex"
        );
        page.finish();
        assert!(matches!(
            direct.resume(copy, &mut memory),
            IoAttempt::Complete(Ok(1))
        ));
        assert!(poll.signal.ready());
        assert!(matches!(
            direct.resume(poll, &mut memory),
            IoAttempt::Complete(Ok(0))
        ));
    }
}

#[test]
fn empty_epoll_checks_user_range_without_faulting_unused_pages_and_uses_native_int_arguments() {
    let target = target();
    let mut v = Vfs::default();
    let event = v.eventfd(1, 0).unwrap();
    let epoll = v.epoll_create(0).unwrap();
    let direct = DirectSyscalls::new(v.direct_descriptors()).with_membership(v.shared_files());
    let mut memory = Memory::default();
    for count in [1, (1u64 << 32) | 1, (i32::MAX / 16) as u64] {
        for address in [0, 0x9000] {
            assert!(matches!(
                direct
                    .start(
                        22,
                        [epoll as u64, address, count, 0, 0, 0],
                        &mut memory,
                        1,
                        &Arc::downgrade(&target),
                        None
                    )
                    .unwrap(),
                IoAttempt::Complete(Ok(0))
            ));
        }
    }
    for count in [0, 0x8000_0000, (i32::MAX / 16) as u64 + 1] {
        assert!(matches!(
            direct
                .start(
                    22,
                    [epoll as u64, 0, count, 0, 0, 0],
                    &mut memory,
                    1,
                    &Arc::downgrade(&target),
                    None
                )
                .unwrap(),
            IoAttempt::Complete(Err(Errno(22)))
        ));
    }
    assert!(matches!(
        direct
            .start(
                22,
                [epoll as u64, trames_memory::ADDRESS_LIMIT, 1, 0, 0, 0],
                &mut memory,
                1,
                &Arc::downgrade(&target),
                None
            )
            .unwrap(),
        IoAttempt::Complete(Err(Errno(14)))
    ));
    v.epoll_ctl(epoll, 1, event, 1, 55).unwrap();
    assert_eq!(
        direct.invoke_epoll_control(
            21,
            [epoll as u64, (1u64 << 32) | 2, event as u64, u64::MAX, 0, 0],
            &memory
        ),
        Some(Ok(0)),
        "native DELETE ignores the user event pointer"
    );
    assert!(v.epoll_wait(epoll, 1, |_, _| Ok(None)).unwrap().is_empty());
}
