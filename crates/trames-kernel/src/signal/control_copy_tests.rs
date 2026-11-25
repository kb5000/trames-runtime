// SPDX-License-Identifier: GPL-3.0-or-later
use super::frame_copy_tests::Faults;
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};

fn call(signals: &Signals, number: u32, args: [u64; 6], sp: u64) -> ControlCall {
    ControlCall::new(
        number,
        args,
        sp,
        signals.actions.shared(),
        signals.io_directory.clone(),
    )
}
fn action(memory: &mut Memory, address: u64, value: Action) {
    memory.write_array(address, value.encode()).unwrap();
}
fn stack(memory: &mut Memory, address: u64, sp: u64, size: u64, flags: u32) {
    let mut bytes = [0; 24];
    bytes[..8].copy_from_slice(&sp.to_le_bytes());
    bytes[8..12].copy_from_slice(&flags.to_le_bytes());
    bytes[16..24].copy_from_slice(&size.to_le_bytes());
    memory.write_array(address, bytes).unwrap();
}

#[test]
fn action_output_retains_the_original_predecessor_and_never_reinstalls_on_resume() {
    let signals = Signals::default();
    let mut memory = Faults::new(0x2000);
    let old = Action {
        handler: 0x4000,
        mask: 0x12340000,
        restorer: 0x8000,
        ..Default::default()
    };
    let next = Action {
        handler: 0x5000,
        flags: 0x80000000,
        mask: 0x56780000,
        ..Default::default()
    };
    signals.actions.set(10, old);
    action(&mut memory.memory, 0x1000, next);
    let mut request = call(&signals, 134, [10, 0x1000, 0x1ff0, 8, 0, 0], 0x10000);
    assert_eq!(request.check(&signals.io, &mut memory), None);
    assert!(!request.ready());
    assert_eq!(
        signals.actions.get(10),
        next,
        "mutation precedes the first actual output byte"
    );
    let later = Action {
        handler: 0x6000,
        ..Default::default()
    };
    signals.actions.set(10, later);
    action(&mut memory.memory, 0x1000, Action::default());
    memory.memory.write(0x1ff0, b"KEEP").unwrap();
    memory.wait.finish();
    assert_eq!(request.check(&signals.io, &mut memory), Some(Ok(0)));
    assert_eq!(signals.actions.get(10), later);
    assert_eq!(memory.memory.read_array::<4>(0x1ff0).unwrap(), *b"KEEP");
    assert_eq!(memory.memory.read_u64(0x2000).unwrap(), old.restorer);
    assert_eq!(memory.memory.read_u64(0x2008).unwrap(), old.mask);
}
#[test]
fn action_input_keeps_its_prefix_but_exchanges_the_predecessor_only_after_input_completes() {
    let signals = Signals::default();
    let mut memory = Faults::new(0x2000);
    let next = Action {
        handler: 0x5000,
        flags: 4,
        restorer: 0x7000,
        mask: 1 << 10,
    };
    action(&mut memory.memory, 0x1ff0, next);
    let mut request = call(&signals, 134, [10, 0x1ff0, 0x1100, 8, 0, 0], 0x10000);
    assert_eq!(request.check(&signals.io, &mut memory), None);
    assert_eq!(signals.actions.get(10), Action::default());
    let predecessor = Action {
        handler: 0x4000,
        ..Default::default()
    };
    signals.actions.set(10, predecessor);
    memory
        .memory
        .write_array(0x1ff0, 0x9999u64.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert_eq!(request.check(&signals.io, &mut memory), Some(Ok(0)));
    assert_eq!(signals.actions.get(10), next);
    assert_eq!(memory.memory.read_u64(0x1100).unwrap(), predecessor.handler);
}
#[test]
fn ignored_signal_is_discarded_before_an_output_wait_and_a_failed_copy_keeps_the_mutation() {
    let signals = Signals::default();
    let mut memory = Faults::new(0x2000);
    signals.io.inbox.enqueue(35, Info::default()).unwrap();
    action(
        &mut memory.memory,
        0x1000,
        Action {
            handler: 1,
            ..Default::default()
        },
    );
    let mut request = call(&signals, 134, [35, 0x1000, 0x1ff0, 8, 0, 0], 0x10000);
    assert_eq!(request.check(&signals.io, &mut memory), None);
    assert!(signals.io.dequeue(1 << 34).is_none());
    signals.io.inbox.enqueue(35, Info::default()).unwrap();
    memory.memory.unmap(0x2000, PAGE_SIZE).unwrap();
    memory.wait.finish();
    assert_eq!(
        request.check(&signals.io, &mut memory),
        Some(Err(Errno(14)))
    );
    assert_eq!(signals.actions.get(35).handler, 1);
    assert!(
        signals.io.dequeue(1 << 34).is_some(),
        "retry does not repeat the earlier discard"
    );
}
#[test]
fn mask_input_keeps_its_entry_predecessor_and_applies_once_to_the_original_task() {
    let mut signals = Signals::default();
    signals.set_mask(1 << 2);
    signals.begin_io();
    let mut memory = Faults::new(0x2000);
    memory
        .memory
        .write_array(0x1ffc, (1u64 << 10).to_le_bytes())
        .unwrap();
    let mut request = call(&signals, 135, [0, 0x1ffc, 0x1100, 8, 0, 0], 0x10000);
    assert_eq!(request.check(&signals.io, &mut memory), None);
    assert_eq!(signals.io.mask(), 1 << 2);
    signals.io.context.lock().unwrap().mask = 1 << 3;
    signals.io.publish_mask(1 << 3);
    memory
        .memory
        .write_array(0x1ffc, 0u32.to_le_bytes())
        .unwrap();
    let other = Signals::default();
    memory.wait.finish();
    assert_eq!(request.check(&other.io, &mut memory), Some(Ok(0)));
    assert_eq!(signals.io.mask(), (1 << 3) | (1 << 10));
    assert_eq!(other.io.mask(), 0);
    assert_eq!(memory.memory.read_u64(0x1100).unwrap(), 1 << 2);
}
#[test]
fn mask_output_keeps_its_original_value_after_state_changes_and_permanent_failure() {
    let mut signals = Signals::default();
    signals.set_mask(0x12340000);
    signals.begin_io();
    let mut memory = Faults::new(0x2000);
    memory
        .memory
        .write_array(0x1000, (1u64 << 15).to_le_bytes())
        .unwrap();
    let mut request = call(&signals, 135, [2, 0x1000, 0x1ffc, 8, 0, 0], 0x10000);
    assert_eq!(request.check(&signals.io, &mut memory), None);
    assert_eq!(signals.io.mask(), 1 << 15);
    signals.io.context.lock().unwrap().mask = 1 << 10;
    signals.io.publish_mask(1 << 10);
    memory.memory.unmap(0x2000, PAGE_SIZE).unwrap();
    memory.wait.finish();
    assert_eq!(
        request.check(&signals.io, &mut memory),
        Some(Err(Errno(14)))
    );
    assert_eq!(signals.io.mask(), 1 << 10);
}
#[test]
fn altstack_output_keeps_its_predecessor_without_replacing_a_later_stack() {
    let signals = Signals::default();
    let mut memory = Faults::new(0x2000);
    stack(&mut memory.memory, 0x1000, 0x6000, 8192, SS_AUTODISARM);
    let mut request = call(&signals, 132, [0x1000, 0x1ff0, 0, 0, 0, 0], 0x10000);
    assert_eq!(request.check(&signals.io, &mut memory), None);
    assert_eq!(
        signals.io.context.lock().unwrap().alt_stack,
        AltStack {
            sp: 0x6000,
            size: 8192,
            flags: SS_AUTODISARM
        }
    );
    let later = AltStack {
        sp: 0x8000,
        size: 16384,
        flags: 0,
    };
    signals.io.context.lock().unwrap().alt_stack = later;
    memory.memory.write(0x1ff0, b"KEEP").unwrap();
    memory.wait.finish();
    assert_eq!(request.check(&signals.io, &mut memory), Some(Ok(0)));
    assert_eq!(signals.io.context.lock().unwrap().alt_stack, later);
    assert_eq!(memory.memory.read_array::<4>(0x1ff0).unwrap(), *b"KEEP");
    assert_eq!(memory.memory.read_u64(0x2000).unwrap(), 0);
}
#[test]
fn pending_bitmap_accepts_native_short_lengths_and_keeps_its_accepted_snapshot() {
    let mut signals = Signals::default();
    signals.set_mask(1 << 34);
    signals.begin_io();
    let mut memory = Faults::new(0x2000);
    signals.io.inbox.enqueue(35, Info::default()).unwrap();
    let mut request = call(&signals, 136, [0x1ffc, 8, 0, 0, 0, 0], 0x10000);
    assert_eq!(request.check(&signals.io, &mut memory), None);
    assert!(signals.io.dequeue(1 << 34).is_some());
    memory.wait.finish();
    assert_eq!(request.check(&signals.io, &mut memory), Some(Ok(0)));
    assert_eq!(memory.memory.read_u64(0x1ffc).unwrap(), 1 << 34);
    for size in 0..=8 {
        memory.memory.write(0x1000, &[0x5a; 8]).unwrap();
        let mut request = call(&signals, 136, [0x1000, size, 0, 0, 0, 0], 0x10000);
        assert_eq!(request.check(&signals.io, &mut memory), Some(Ok(0)));
        let bytes = memory.memory.read_array::<8>(0x1000).unwrap();
        assert!(bytes[..size as usize].iter().all(|b| *b == 0));
        assert!(bytes[size as usize..].iter().all(|b| *b == 0x5a));
    }
    assert_eq!(
        call(&signals, 136, [u64::MAX, 0, 0, 0, 0, 0], 0).check(&signals.io, &mut memory),
        Some(Ok(0))
    );
}
#[test]
fn validation_uses_native_input_effect_and_output_error_order() {
    let signals = Signals::default();
    let mut memory = Faults::new(0x2000);
    for (number, args, expected) in [
        (134, [9, u64::MAX, u64::MAX, 8, 0, 0], 14),
        (134, [9, u64::MAX, u64::MAX, 16, 0, 0], 22),
        (135, [99, u64::MAX, u64::MAX, 8, 0, 0], 14),
        (135, [99, 0x1000, u64::MAX, 8, 0, 0], 22),
        (136, [u64::MAX, 9, 0, 0, 0, 0], 22),
    ] {
        assert_eq!(
            call(&signals, number, args, 0x10000).check(&signals.io, &mut memory),
            Some(Err(Errno(expected)))
        );
    }
    for size in [2048, 5119, 5120] {
        stack(&mut memory.memory, 0x1000, 0x6000, size, 0);
        assert_eq!(
            call(&signals, 132, [0x1000, 0, 0, 0, 0, 0], 0x10000).check(&signals.io, &mut memory),
            Some(if size < 5120 { Err(Errno(12)) } else { Ok(0) })
        );
    }
    stack(&mut memory.memory, 0x1000, 0, 0, 8);
    assert_eq!(
        call(&signals, 132, [0x1000, u64::MAX, 0, 0, 0, 0], 0x6800).check(&signals.io, &mut memory),
        Some(Err(Errno(1)))
    );
}
#[test]
fn cancelling_control_keeps_accepted_effects_and_never_resumes_output_into_a_new_task() {
    let signals = Signals::default();
    let mut memory = Faults::new(0x2000);
    action(
        &mut memory.memory,
        0x1000,
        Action {
            handler: 0x5000,
            ..Default::default()
        },
    );
    let mut request = call(&signals, 134, [10, 0x1000, 0x1ff0, 8, 0, 0], 0x10000);
    assert_eq!(request.check(&signals.io, &mut memory), None);
    request.cancel();
    memory.memory.write(0x1ff0, b"KEEP").unwrap();
    memory.memory.write(0x2000, &[0x5a; 16]).unwrap();
    memory.wait.finish();
    let other = Signals::default();
    assert_eq!(request.check(&other.io, &mut memory), Some(Err(Errno(4))));
    assert_eq!(memory.memory.read_array::<4>(0x1ff0).unwrap(), *b"KEEP");
    assert_eq!(memory.memory.read_array::<16>(0x2000).unwrap(), [0x5a; 16]);
    assert_eq!(signals.actions.get(10).handler, 0x5000);
    assert_eq!(other.actions.get(10).handler, 0);
}

#[test]
fn sigreturn_ignores_stack_validation_errors_and_restores_the_original_cpu_and_mask() {
    use trames_execution::Aarch64State;
    for (flags, size) in [(8u32, 8192u64), (0, 5119)] {
        let mut signals = Signals {
            alt_stack: AltStack {
                sp: 0x2000,
                size: 8192,
                flags: 0,
            },
            ..Default::default()
        };
        signals.set_mask(1 << 3);
        let old_stack = signals.alt_stack;
        let mut memory = Memory::default();
        memory.map(0x1000, 16 * PAGE_SIZE, Permissions::RW).unwrap();
        let mut cpu = Aarch64State {
            sp: 0x10000,
            pc: 0x4000,
            ..Default::default()
        };
        let old_cpu = cpu.clone();
        signals
            .enter(
                &mut cpu,
                &mut memory,
                10,
                Info::default(),
                Action {
                    handler: 0x5000,
                    ..Default::default()
                },
            )
            .unwrap();
        stack(&mut memory, cpu.sp + 144, 0x6000, size, flags);
        signals.restore(&mut cpu, &memory).unwrap();
        assert_eq!(cpu, old_cpu);
        assert_eq!(signals.mask, 1 << 3);
        assert_eq!(signals.alt_stack, old_stack);
        assert_eq!(signals.frames, 0);
    }
}
