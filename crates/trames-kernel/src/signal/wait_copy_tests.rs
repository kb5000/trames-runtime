// SPDX-License-Identifier: GPL-3.0-or-later
use super::frame_copy_tests::Faults;
use super::*;
use std::time::Instant;

#[test]
fn siginfo_page_wait_keeps_the_consumed_record_without_redequeue_or_timeout_pulses() {
    let mut memory = Faults::new(0x2000);
    let signals = Signals::default();
    let task = &signals.io;
    task.inbox
        .enqueue(
            35,
            Info {
                user: Some([11; 48]),
                ..Default::default()
            },
        )
        .unwrap();
    task.inbox
        .enqueue(
            35,
            Info {
                user: Some([22; 48]),
                ..Default::default()
            },
        )
        .unwrap();
    let mut call = WaitCall::accepted(SignalWait::Timed {
        mask: 1 << 34,
        info: 0x1ff0,
        deadline: Some(Instant::now()),
    });
    let namespace = trames_vfs::Vfs::default().pid_namespace().clone();
    assert_eq!(call.check(task, &mut memory, &namespace), None);
    assert!(!call.interruptible());
    assert!(call.deadline().is_none());
    assert!(!call.ready(task));
    assert_eq!(task.dequeue(1 << 34).unwrap().1.user.unwrap(), [22; 48]);
    task.inbox
        .enqueue(
            35,
            Info {
                user: Some([33; 48]),
                ..Default::default()
            },
        )
        .unwrap();
    memory.memory.write(0x1ff0, b"KEEP").unwrap();
    memory.wait.finish();
    assert_eq!(call.check(task, &mut memory, &namespace), Some(Ok(35)));
    assert_eq!(memory.memory.read_array::<4>(0x1ff0).unwrap(), *b"KEEP");
    assert_eq!(memory.memory.read_array::<32>(0x2000).unwrap(), [11; 32]);
    assert_eq!(task.dequeue(1 << 34).unwrap().1.user.unwrap(), [33; 48]);
    assert_eq!(call.check(task, &mut memory, &namespace), Some(Ok(35)));
}

#[test]
fn sigwait_input_retains_mask_and_timeout_prefix_before_consuming_any_signal() {
    let mut memory = Faults::new(0x2000);
    memory
        .memory
        .write_array(0x1000, (1u64 << 34).to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(0x1ff8, 0u64.to_le_bytes())
        .unwrap();
    let signals = Signals::default();
    signals.io.inbox.enqueue(35, Info::default()).unwrap();
    let namespace = trames_vfs::Vfs::default().pid_namespace().clone();
    let mut call = WaitCall::new(137, [0x1000, 0, 0x1ff8, 8, 0, 0]);
    assert_eq!(call.check(&signals.io, &mut memory, &namespace), None);
    assert_ne!(signals.io.pending_bits() & (1 << 34), 0);
    memory
        .memory
        .write_array(0x1000, 0u64.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(0x1ff8, u64::MAX.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert_eq!(
        call.check(&signals.io, &mut memory, &namespace),
        Some(Ok(35))
    );
}

#[test]
fn suspend_mask_import_waits_for_its_original_input_and_keeps_the_baseline_for_the_handler() {
    let mut memory = Faults::new(0x2000);
    memory
        .memory
        .write_array(0x1ffc, (1u64 << 10).to_le_bytes())
        .unwrap();
    let mut signals = Signals::default();
    signals.set_mask(1 << 2);
    signals.begin_io();
    let namespace = trames_vfs::Vfs::default().pid_namespace().clone();
    let mut call = WaitCall::new(133, [0x1ffc, 8, 0, 0, 0, 0]);
    assert_eq!(call.check(&signals.io, &mut memory, &namespace), None);
    assert_eq!(signals.io.mask(), 1 << 2);
    memory
        .memory
        .write_array(0x1ffc, (1u32 << 20).to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert_eq!(call.check(&signals.io, &mut memory, &namespace), None);
    assert_eq!(signals.io.mask(), 1 << 10);
    assert_eq!(signals.io.context.lock().unwrap().wait_mask, Some(1 << 2));
    drop(call);
    assert_eq!(signals.io.mask(), 1 << 10);
}
