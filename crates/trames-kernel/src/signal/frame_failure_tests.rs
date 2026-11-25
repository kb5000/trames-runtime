// SPDX-License-Identifier: GPL-3.0-or-later
use super::frame_copy_tests::Faults;
use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use trames_execution::{Aarch64State, Registers};
use trames_memory::{Memory, Permissions, PAGE_SIZE};

#[test]
fn failed_signal_frame_forces_the_original_thread_and_resets_only_native_dispositions() {
    for (signal, handler, mask, expected) in [
        (35, 0x5000, 0, 0x5000),
        (11, 0x5000, 0, 0),
        (35, 0x5000, 1 << 10, 0),
        (35, 1, 0, 0),
        (35, 0, 0, 0),
    ] {
        let mut signals = Signals::default();
        signals.set_mask(mask | (1 << 2));
        signals.begin_io();
        let action = Action {
            handler,
            flags: 0x80000004,
            restorer: 0x6000,
            mask: 1 << 15,
        };
        signals.actions.set(11, action);
        signals.io.inbox.enqueue(2, Info::default()).unwrap();
        signals.actions.failed_frame(&signals.io, signal);
        assert_eq!(
            signals.actions.get(11),
            Action {
                handler: expected,
                ..action
            }
        );
        assert_eq!(signals.io.mask(), 1 << 2);
        assert_eq!(signals.io.context.lock().unwrap().mask, 1 << 2);
        assert_eq!(signals.io.next_delivery(u64::MAX), Some((11, false)));
        let info = signals.io.take(11, false).unwrap();
        assert_eq!(
            (info.code, info.fault, info.sender, info.uid),
            (128, Some(0), 0, 0)
        );
        assert_ne!(signals.io.pending_bits() & (1 << 1), 0);
    }
}
#[test]
fn forced_frame_signal_preserves_standard_coalescing_and_the_process_queue() {
    let signals = Signals::default();
    signals.actions.set(
        11,
        Action {
            handler: 0x5000,
            ..Default::default()
        },
    );
    signals
        .io
        .inbox
        .enqueue(
            11,
            Info {
                code: -1,
                sender: 77,
                ..Default::default()
            },
        )
        .unwrap();
    signals
        .io
        .process()
        .enqueue(
            11,
            Info {
                code: 5,
                fault: Some(0x9000),
                ..Default::default()
            },
        )
        .unwrap();
    signals.actions.failed_frame(&signals.io, 35);
    assert_eq!(signals.io.inbox.peek(11).unwrap().code, -1);
    assert_eq!(signals.io.process().peek(11).unwrap().code, 5);
    assert_eq!(signals.actions.get(11).handler, 0x5000);
}
struct Wake {
    actions: Actions,
    calls: AtomicUsize,
}
impl trames_vfs::IoWake for Wake {
    fn wake_io(&self, _: &Arc<trames_vfs::IoSignal>) {
        let _ = self.actions.get(11);
        self.calls.fetch_add(1, Ordering::Relaxed);
    }
}
#[test]
fn forced_delivery_wakes_after_releasing_its_original_sighand_lock() {
    let signals = Signals::default();
    let target = Arc::new(Wake {
        actions: signals.actions.shared(),
        calls: AtomicUsize::new(0),
    });
    let authority: Arc<dyn trames_vfs::IoWake> = target.clone();
    let signal = trames_vfs::IoSignal::new(1, Arc::downgrade(&authority));
    let _subscription = signals.io.inbox.subscribe(&signal);
    signals.actions.failed_frame(&signals.io, 35);
    assert_eq!(target.calls.load(Ordering::Relaxed), 1);
}
#[test]
fn bad_return_metadata_matches_find_vma_for_holes_reservations_tags_and_live_additions() {
    let mut memory = Memory::default();
    memory.map(0x4000, PAGE_SIZE, Permissions::NONE).unwrap();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    let view = memory.parallel_view(&mut Default::default()).unwrap();
    for (address, code) in [
        (0, 2),
        (0x4000, 2),
        (0x6000, 2),
        (0x10000, 2),
        (0x11000, 1),
        (0xaa00000000004000, 2),
    ] {
        let expected = Fault {
            signal: 11,
            code,
            address: address & 0x00ff_ffff_ffff_ffff,
        };
        assert_eq!(Fault::bad_frame(address, &memory), expected);
        assert_eq!(Fault::bad_frame(address, &view), expected);
    }
    let resident = memory.resident_bytes();
    memory.map_anonymous_live(0x200000, PAGE_SIZE).unwrap();
    assert_eq!(Fault::bad_frame(0x180000, &view).code, 2);
    assert_eq!(Fault::bad_frame(0x201000, &view).code, 1);
    assert_eq!(
        memory.resident_bytes(),
        resident,
        "classification must not materialize anonymous bytes"
    );
}
#[test]
fn a_frame_copy_wait_preserves_the_original_signal_until_an_actual_failure() {
    let mut signals = Signals::default();
    signals.actions.set(
        11,
        Action {
            handler: 0x5000,
            ..Default::default()
        },
    );
    let mut memory = Faults::new(0x2000);
    let mut cpu = Aarch64State {
        sp: 0x3000,
        pc: 0x4000,
        ..Default::default()
    };
    let original = cpu.clone();
    assert!(signals
        .enter_sme_pending(
            &mut cpu,
            &mut memory,
            35,
            Info::default(),
            Action {
                handler: 0x6000,
                ..Default::default()
            },
            None
        )
        .unwrap()
        .is_some());
    assert_eq!(signals.io.pending_bits() & (1 << 10), 0);
    memory.memory.unmap(0x2000, PAGE_SIZE).unwrap();
    memory.wait.finish();
    assert_eq!(signals.resume_frame(&mut cpu, &mut memory), Err(Errno(14)));
    assert_eq!(cpu, original);
    assert_eq!(signals.frames, 0);
    assert_eq!(
        signals.actions.get(11).handler,
        0x5000,
        "failure remembers signal 35, not an invented recursive SIGSEGV"
    );
    assert_eq!(signals.io.inbox.peek(11).unwrap().code, 128);
    assert!(!signals.io.has_pending_frame());
}
#[test]
fn sigreturn_accepts_a_valid_user_frame_without_a_prior_internal_frame_count() {
    let mut signals = Signals::default();
    let mut memory = Memory::default();
    memory.map(0x1000, 16 * PAGE_SIZE, Permissions::RW).unwrap();
    let mut cpu = Aarch64State {
        sp: 0x10000,
        pc: 0x4000,
        ..Default::default()
    };
    cpu.set_x(0, 77);
    let original = cpu.clone();
    signals
        .enter(
            &mut cpu,
            &mut memory,
            35,
            Info::default(),
            Action {
                handler: 0x5000,
                ..Default::default()
            },
        )
        .unwrap();
    signals.frames = 0;
    signals.restore(&mut cpu, &memory).unwrap();
    assert_eq!(cpu, original);
    assert_eq!(signals.frames, 0);
}
