// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_execution::Aarch64State;
use trames_memory::{Memory, Permissions};

#[test]
fn old_mask_receipts_and_snapshots_cannot_restore_over_a_new_original_call() {
    let mut signals = Signals::default();
    let baseline = 1 << 2;
    signals.set_mask(baseline);
    signals.begin_io();
    let task = signals.io.clone();
    let first = trames_vfs::TaskSignal::temporary_mask(task.clone(), 1 << 11).unwrap();
    let snapshot = first.clone();
    assert_eq!(task.mask(), 1 << 11);
    let second =
        trames_vfs::TaskSignal::temporary_mask(task.clone(), (1 << 14) | UNBLOCKABLE).unwrap();
    first.finish();
    drop(first);
    assert_eq!(
        task.mask(),
        1 << 14,
        "retired receipt cannot undo the new operation"
    );
    second.finish();
    assert_eq!(task.mask(), baseline);
    let third = trames_vfs::TaskSignal::temporary_mask(task.clone(), 1 << 16).unwrap();
    snapshot.finish();
    drop((snapshot, second));
    assert_eq!(task.mask(), 1 << 16);
    drop(third);
    assert_eq!(
        task.mask(),
        baseline,
        "cancellation returns only its own original mask"
    );
    assert_eq!(task.context.lock().unwrap().wait_mask, None);
}

#[test]
fn interrupted_mask_reaches_the_handler_but_its_frame_keeps_the_original_restore_mask() {
    let mut signals = Signals::default();
    let baseline = 1 << 2;
    let temporary = 1 << 11;
    signals.set_mask(baseline);
    signals.begin_io();
    let task = signals.io.clone();
    let lease = trames_vfs::TaskSignal::temporary_mask(task.clone(), temporary).unwrap();
    lease.interrupted();
    drop(lease);
    assert_eq!(task.mask(), temporary);
    assert_eq!(task.context.lock().unwrap().wait_mask, Some(baseline));
    signals.finish_io();
    let mut memory = Memory::default();
    memory.map(0x1000, 0x10000, Permissions::RW).unwrap();
    let mut state = Aarch64State {
        sp: 0x10000,
        pc: 0x1234,
        ..Default::default()
    };
    signals
        .enter(
            &mut state,
            &mut memory,
            10,
            Info::default(),
            Action {
                handler: 0x2000,
                mask: 1 << 15,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(memory.read_u64(state.sp + 168).unwrap(), baseline);
    assert_eq!(signals.mask, temporary | (1 << 15) | (1 << 9));
    signals.begin_io();
    assert_eq!(task.context.lock().unwrap().wait_mask, None);
    assert_eq!(task.mask(), signals.mask);
}
