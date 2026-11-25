// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::signal::frame_copy_tests::Faults;
use trames_memory::PAGE_SIZE;
fn authority() -> (Vfs, Authority) {
    let vfs = Vfs::default();
    let authority = Authority {
        directory: Arc::default(),
        limits: Limits::new(&vfs),
        namespace: vfs.pid_namespace().clone(),
        pid: 1,
        credentials: Credentials::default(),
        fixed: Fixed {
            address_space: u64::MAX,
            stack: 8 << 20,
            tasks: 1024,
        },
    };
    (vfs, authority)
}
fn pair(memory: &mut impl CpuMemory, address: u64, value: Pair) {
    memory.write_array(address, encode(value)).unwrap();
}
#[test]
fn exchange_and_live_enforcement_precede_output_wait_and_resume_keeps_old_snapshot() {
    let (vfs, authority) = authority();
    let limits = authority.limits.clone();
    limits.set(7, (64, 128));
    let mut memory = Faults::new(0x2000);
    pair(&mut memory.memory, 0x1100, (8, 16));
    let mut call = Call::new(authority, 261, [0, 7, 0x1100, 0x1ff8, 0, 0]);
    assert_eq!(call.check(&mut memory), None);
    assert!(!call.ready());
    assert_eq!(limits.get(7), (8, 16));
    assert_eq!(vfs.descriptor_limit(), 8);
    assert_eq!(memory.memory.read_u64(0x1ff8).unwrap(), 64);
    limits.set(7, (4, 8));
    pair(&mut memory.memory, 0x1100, (1, 2));
    memory
        .memory
        .write_array(0x1ff8, 99u64.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
    assert_eq!(limits.get(7), (4, 8));
    assert_eq!(memory.memory.read_u64(0x1ff8).unwrap(), 99);
    assert_eq!(memory.memory.read_u64(0x2000).unwrap(), 128);
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
}
#[test]
fn import_keeps_prefix_and_target_is_looked_up_only_after_complete_input() {
    let (_vfs, authority) = authority();
    let old = Limits::new(&Vfs::default());
    let replacement = Limits::new(&Vfs::default());
    let first = Arc::new(crate::task::Presence::default());
    authority
        .directory
        .publish(42, &first, &old, &Arc::default());
    let mut memory = Faults::new(0x2000);
    pair(&mut memory.memory, 0x1ff8, (8, 16));
    let mut call = Call::new(
        authority.clone(),
        261,
        [42, 7 | (1u64 << 32), 0x1ff8, 0x1100, 0, 0],
    );
    assert_eq!(call.check(&mut memory), None);
    assert_eq!(old.get(7).0, trames_vfs::DEFAULT_MAX_FDS as u64);
    drop(first);
    let next = Arc::new(crate::task::Presence::default());
    authority
        .directory
        .publish(42, &next, &replacement, &Arc::default());
    memory
        .memory
        .write_array(0x1ff8, 99u64.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
    assert_eq!(replacement.get(7), (8, 16));
    assert_eq!(old.get(7).0, trames_vfs::DEFAULT_MAX_FDS as u64);
}
#[test]
fn original_target_survives_output_wait_without_keeping_pid_visible_or_retargeting_reuse() {
    let (_vfs, authority) = authority();
    let old = Limits::new(&Vfs::default());
    old.set(7, (64, 128));
    let first = Arc::new(crate::task::Presence::default());
    authority
        .directory
        .publish(42, &first, &old, &Arc::default());
    let mut memory = Faults::new(0x2000);
    pair(&mut memory.memory, 0x1100, (8, 16));
    let mut call = Call::new(authority.clone(), 261, [42, 7, 0x1100, 0x1ff8, 0, 0]);
    assert_eq!(call.check(&mut memory), None);
    assert_eq!(old.get(7), (8, 16));
    drop(first);
    assert_eq!(
        authority.call(261, [42, 7, 0, 0, 0, 0], &mut memory.memory),
        Err(Errno(3))
    );
    let replacement = Limits::new(&Vfs::default());
    let second = Arc::new(crate::task::Presence::default());
    authority
        .directory
        .publish(42, &second, &replacement, &Arc::default());
    let weak = Arc::downgrade(&old);
    drop(old);
    assert!(weak.upgrade().is_some());
    memory.wait.finish();
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
    assert!(weak.upgrade().is_none());
    assert_eq!(replacement.get(7).0, trames_vfs::DEFAULT_MAX_FDS as u64);
    assert_eq!(memory.memory.read_u64(0x2000).unwrap(), 128);
}
#[test]
fn permanent_old_value_fault_keeps_new_limits_and_null_legacy_pointers_are_not_ignored() {
    let (vfs, authority) = authority();
    let mut memory = Faults::new(0x2000);
    pair(&mut memory.memory, 0x1100, (8, 16));
    assert_eq!(
        authority.call(261, [0, 7, 0x1100, 0x90000, 0, 0], &mut memory.memory),
        Err(Errno(14))
    );
    assert_eq!(authority.limits.get(7), (8, 16));
    assert_eq!(vfs.descriptor_limit(), 8);
    assert_eq!(
        authority.call(163, [7, 0, 0, 0, 0, 0], &mut memory.memory),
        Err(Errno(14))
    );
    assert_eq!(
        authority.call(164, [999, 0, 0, 0, 0, 0], &mut memory.memory),
        Err(Errno(14))
    );
    let mut call = Call::new(authority.clone(), 261, [0, 7, 0x1100, 0x1ff8, 0, 0]);
    assert_eq!(call.check(&mut memory), None);
    memory.memory.unmap(0x2000, PAGE_SIZE).unwrap();
    memory.wait.finish();
    assert_eq!(call.check(&mut memory), Some(Err(Errno(14))));
    assert_eq!(authority.limits.get(7), (8, 16));
}
#[test]
fn input_fault_precedes_pid_and_permission_but_pair_validation_follows_them() {
    let (_vfs, mut authority) = authority();
    let mut memory = Faults::new(0x2000);
    assert_eq!(
        authority.call(261, [999, 999, 0x90000, 0, 0, 0], &mut memory.memory),
        Err(Errno(14))
    );
    pair(&mut memory.memory, 0x1100, (9, 8));
    assert_eq!(
        authority.call(261, [999, 999, 0x1100, 0, 0, 0], &mut memory.memory),
        Err(Errno(3))
    );
    let target = Limits::new(&Vfs::default());
    let life = Arc::new(crate::task::Presence::default());
    authority
        .directory
        .publish(42, &life, &target, &Arc::default());
    authority.credentials = Credentials::user(1000, 1000);
    assert_eq!(
        authority.call(261, [42, 999, 0x1100, 0, 0, 0], &mut memory.memory),
        Err(Errno(1))
    );
    assert_eq!(
        authority.call(261, [0, 7, 0x1100, 0, 0, 0], &mut memory.memory),
        Err(Errno(22))
    );
}
#[test]
fn cancellation_before_and_after_exchange_does_not_repeat_or_roll_back_the_effect() {
    for output in [false, true] {
        let (vfs, authority) = authority();
        let limits = authority.limits.clone();
        limits.set(7, (64, 128));
        let mut memory = Faults::new(0x2000);
        pair(
            &mut memory.memory,
            if output { 0x1100 } else { 0x1ff8 },
            (8, 16),
        );
        let args = if output {
            [0, 7, 0x1100, 0x1ff8, 0, 0]
        } else {
            [0, 7, 0x1ff8, 0, 0, 0]
        };
        let mut call = Call::new(authority, 261, args);
        assert_eq!(call.check(&mut memory), None);
        call.cancel();
        memory.wait.finish();
        assert_eq!(call.check(&mut memory), Some(Err(Errno(4))));
        assert_eq!(limits.get(7), if output { (8, 16) } else { (64, 128) });
        assert_eq!(vfs.descriptor_limit(), if output { 8 } else { 64 });
    }
}
#[test]
fn input_output_alias_keeps_both_imported_words_and_exports_one_predecessor() {
    let (_vfs, authority) = authority();
    authority.limits.set(7, (64, 128));
    let mut memory = Faults::new(0x2000);
    pair(&mut memory.memory, 0x1ff8, (8, 16));
    let mut call = Call::new(authority.clone(), 261, [0, 7, 0x1ff8, 0x1ff8, 0, 0]);
    assert_eq!(call.check(&mut memory), None);
    memory
        .memory
        .write_array(0x1ff8, 99u64.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
    assert_eq!(authority.limits.get(7), (8, 16));
    assert_eq!(
        memory.memory.read_array::<16>(0x1ff8).unwrap(),
        encode((64, 128))
    );
}
