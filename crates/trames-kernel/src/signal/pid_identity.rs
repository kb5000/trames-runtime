// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};
use trames_vfs::Vfs;

fn nested() -> (Vfs, Signals) {
    let mut init = Vfs::default();
    init.unshare_pid().unwrap();
    init.activate_child_pid(100).unwrap();
    let signals = Signals::default();
    signals.publish_policy(init.pid_namespace(), true);
    signals.io.publish_mask(u64::MAX);
    (init, signals)
}

#[test]
fn reaped_sender_identity_survives_dequeue_until_each_abi_consumer_finishes() {
    for shared in [false, true] {
        for reader in 0..3 {
            let (init, signals) = nested();
            let namespace = init.pid_namespace().clone();
            let mut sender = init.clone();
            sender.activate_child_pid(200).unwrap();
            signals
                .io
                .job_signal(
                    35,
                    shared,
                    Info {
                        sender: 200,
                        ..Default::default()
                    },
                    false,
                )
                .unwrap();
            drop(sender);
            assert_eq!(namespace.local(200), 2);
            match reader {
                0 => {
                    let queued = signals.io.take(35, shared).unwrap();
                    assert_eq!(namespace.local(queued.sender), 2);
                    std::thread::spawn(move || drop(queued)).join().unwrap();
                }
                1 => {
                    let reader = signals.reader(&namespace);
                    let bytes = std::thread::spawn(move || reader.take(1 << 34).unwrap())
                        .join()
                        .unwrap();
                    assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 2);
                }
                _ => {
                    let mut memory = Memory::default();
                    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
                    let wait = SignalWait::Timed {
                        mask: 1 << 34,
                        info: 0x10000,
                        deadline: None,
                    };
                    assert_eq!(
                        wait.check(&signals.io, &mut memory, &namespace),
                        Some(Ok(35))
                    );
                    assert_eq!(u32::from_le_bytes(memory.read_array(0x10010).unwrap()), 2);
                }
            }
            assert_eq!(
                namespace.local(200),
                0,
                "ABI completion releases the last sender reference"
            );
        }
    }
}

#[test]
fn coalesced_and_discarded_signals_release_only_their_own_sender_references() {
    let (init, signals) = nested();
    let mut first = init.clone();
    first.activate_child_pid(200).unwrap();
    let mut second = init.clone();
    second.activate_child_pid(201).unwrap();
    for sender in [200, 201] {
        signals
            .io
            .job_signal(
                10,
                false,
                Info {
                    sender,
                    ..Default::default()
                },
                false,
            )
            .unwrap();
    }
    drop(first);
    drop(second);
    assert_eq!(init.visible_pid(200), 2);
    assert_eq!(
        init.visible_pid(201),
        0,
        "coalescing retains only the first siginfo"
    );
    signals.io.inbox.discard(10);
    assert_eq!(init.visible_pid(200), 0);
}

#[test]
fn group_and_session_members_retain_identity_after_leader_task_retires() {
    let (init, member) = nested();
    let mut leader = init.clone();
    leader.activate_child_pid(200).unwrap();
    let mut task = init.clone();
    task.activate_child_pid(201).unwrap();
    let namespace = init.pid_namespace();
    member
        .io
        .retain_pid_references(namespace, [201, 201, 200, 200]);
    member.io.set_session(200);
    member.io_directory.publish(&member.io, 201, 201, 200, 0, 0);
    drop(leader);
    assert_eq!(init.visible_pid(200), 2);
    // setpgid alone must not discard the still-referenced session leader.
    member
        .io
        .retain_pid_references(namespace, [201, 201, 201, 200]);
    member.io.set_group(201);
    member.io_directory.publish(&member.io, 201, 201, 201, 0, 0);
    assert_eq!(init.visible_pid(200), 2);
    member
        .io
        .retain_pid_references(namespace, [201, 201, 201, 201]);
    member.io.set_session(201);
    assert_eq!(init.visible_pid(200), 0);
    assert_eq!(init.visible_pid(201), 3);
}
