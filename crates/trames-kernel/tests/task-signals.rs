// SPDX-License-Identifier: GPL-3.0-or-later
use trames_execution::Aarch64State;
use trames_kernel::signal::{Action, AltStack, Info, Signals, SS_AUTODISARM, SS_DISABLE};
use trames_memory::{Memory, Permissions, PAGE_SIZE};
use trames_vfs::Errno;

#[test]
fn fork_and_exec_preserve_task_ownership_without_copying_pending_signals() {
    let mut parent = Signals {
        mask: 1 << 11,
        frames: 2,
        alt_stack: AltStack {
            sp: 0x8000,
            size: 0x4000,
            flags: SS_AUTODISARM,
        },
        ..Default::default()
    };
    parent.actions.set_handler(10, 0x4000);
    parent.actions.set_handler(12, 1);
    parent.pending.enqueue(10, Info::default()).unwrap();
    parent
        .shared_pending
        .borrow_mut()
        .enqueue(12, Info::default())
        .unwrap();
    let mut fork = parent.fork(false);
    let shared = parent.fork(true);
    parent.actions.set_handler(10, 0x5000);
    assert_eq!(fork.actions.get(10).handler, 0x4000);
    assert_eq!(shared.actions.get(10).handler, 0x5000);
    assert_eq!(fork.pending_bits(), 0);
    assert_eq!(shared.pending_bits(), 0);
    assert_eq!(fork.frames, 2);
    assert_eq!(fork.alt_stack, parent.alt_stack);
    fork.exec();
    assert_eq!(fork.actions.get(10).handler, 0);
    assert_eq!(fork.actions.get(12).handler, 1);
    assert_eq!(fork.mask, 1 << 11);
    assert_eq!(fork.frames, 0);
    assert_eq!(fork.alt_stack.flags, SS_DISABLE);
    assert_ne!(parent.pending_bits(), 0);
    assert_eq!(parent.frames, 2);
}

#[test]
fn failed_frame_publication_and_malformed_return_leave_complete_task_state_intact() {
    let mut memory = Memory::default();
    memory.map(0x1000, 4 * PAGE_SIZE, Permissions::R).unwrap();
    let original = Aarch64State {
        pc: 0x8000,
        sp: 0x5000 - 8,
        nzcv: 0x60000000,
        registers: [0x1234; 31],
        vectors: [0x0123456789abcdef; 32],
        fpcr: 1 << 22,
        fpsr: 0x10,
        tpidr_el0: 0xaabb,
        tpidr2_el0: 0xccdd,
    };
    let mut state = original.clone();
    let action = Action {
        handler: 0x9000,
        flags: 0x80000000,
        ..Default::default()
    };
    let mut signals = Signals {
        mask: 1 << 11,
        ..Default::default()
    };
    signals.actions.set(10, action);
    assert_eq!(
        signals.enter(&mut state, &mut memory, 10, Info::default(), action),
        Err(Errno(14))
    );
    assert_eq!(state, original);
    assert_eq!(signals.mask, 1 << 11);
    assert_eq!(signals.frames, 0);
    assert_eq!(signals.actions.get(10), action);
    memory
        .protect(0x1000, 4 * PAGE_SIZE, Permissions::RW)
        .unwrap();
    signals
        .enter(&mut state, &mut memory, 10, Info::default(), action)
        .unwrap();
    let entered = state.clone();
    let mask = signals.mask;
    memory.write(state.sp + 592, &[0; 4]).unwrap();
    assert_eq!(signals.restore(&mut state, &memory), Err(Errno(14)));
    assert_eq!(state, entered);
    assert_eq!(signals.mask, mask);
    assert_eq!(signals.frames, 1);
    memory
        .write(state.sp + 592, &0x46508001u32.to_le_bytes())
        .unwrap();
    signals.restore(&mut state, &memory).unwrap();
    assert_eq!(state, original);
    assert_eq!(signals.mask, 1 << 11);
    assert_eq!(signals.frames, 0);
}
