// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::direct::file::copyout_tests::{install, Deferred};
use trames_memory::{Memory, Permissions, PAGE_SIZE};
use trames_vfs::{KeyOperation, KeyResult};
fn memory() -> (Memory, Arc<Deferred>) {
    let mut memory = Memory::default();
    memory.map(0x1000, 0x2000, Permissions::RW).unwrap();
    let page = install(&mut memory, 0x3000);
    (memory, page)
}
fn description(keys: &SessionKeys, registry: &KeyRegistry, c: &Credentials, id: i32) -> Vec<u8> {
    let KeyResult::Description(bytes) = keys
        .access(registry, c, id, KeyOperation::Describe)
        .unwrap()
    else {
        panic!("description");
    };
    bytes
}
#[test]
fn set_name_keeps_imported_bytes_and_publishes_only_once_after_complete_input() {
    let (mut memory, page) = memory();
    let name = TaskName::default();
    name.set(b"before");
    memory.write(0x2ff8, b"original").unwrap();
    let mut call = TaskCopyCall::name(name.clone(), [15, 0x2ff8, 0, 0, 0, 0]);
    assert_eq!(call.check(&mut memory), None);
    assert_eq!(name.get(), b"before");
    memory.write(0x2ff8, b"replaced").unwrap();
    page.finish();
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
    assert_eq!(name.get(), b"original");
    name.set(b"after");
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
    assert_eq!(name.get(), b"after");
}
#[test]
fn get_name_keeps_original_snapshot_and_actual_prefix_on_success_or_permanent_error() {
    for fail in [false, true] {
        let (mut memory, page) = memory();
        let name = TaskName::default();
        name.set(b"original-tail");
        let mut call = TaskCopyCall::name(name.clone(), [16, 0x2ff8, 0, 0, 0, 0]);
        assert_eq!(call.check(&mut memory), None);
        assert_eq!(memory.read_array::<8>(0x2ff8).unwrap(), *b"original");
        name.set(b"replacement");
        memory.write(0x2ff8, &[0x77; 8]).unwrap();
        if fail {
            memory.unmap(0x3000, PAGE_SIZE).unwrap();
        }
        page.finish();
        assert_eq!(
            call.check(&mut memory),
            Some(if fail { Err(Errno(14)) } else { Ok(0) })
        );
        assert_eq!(memory.read_array::<8>(0x2ff8).unwrap(), [0x77; 8]);
        if !fail {
            assert_eq!(memory.read_array::<8>(0x3000).unwrap(), *b"-tail\0\0\0");
        }
        assert_eq!(name.get(), b"replacement");
    }
}
#[test]
fn name_input_cancellation_and_permanent_failure_do_not_publish_a_partial_name() {
    for cancel in [false, true] {
        let (mut memory, page) = memory();
        let name = TaskName::default();
        name.set(b"before");
        memory.write(0x2ff8, b"original").unwrap();
        let mut call = TaskCopyCall::name(name.clone(), [15, 0x2ff8, 0, 0, 0, 0]);
        assert_eq!(call.check(&mut memory), None);
        if cancel {
            call.cancel();
        } else {
            memory.unmap(0x3000, PAGE_SIZE).unwrap();
        }
        page.finish();
        assert_eq!(
            call.check(&mut memory),
            Some(Err(Errno(if cancel { 4 } else { 14 })))
        );
        assert_eq!(name.get(), b"before");
    }
}
#[test]
fn join_keyring_keeps_original_name_fragments_credentials_and_one_selection_change() {
    let (mut memory, page) = memory();
    let keys = SessionKeys::default();
    let registry = Arc::new(KeyRegistry::default());
    let mut credentials = Credentials::user(1000, 2000);
    let old = keys
        .join(&registry, &credentials, Some(b"before".to_vec()))
        .unwrap();
    memory.write(0x2ff8, b"original").unwrap();
    let mut call = TaskCopyCall::keys(
        keys.clone(),
        registry.clone(),
        credentials.clone(),
        [1, 0x2ff8, 0, 0, 0, 0],
    );
    assert_eq!(call.check(&mut memory), None);
    assert!(
        matches!(keys.access(&registry,&credentials,-3,KeyOperation::Lookup(false)).unwrap(),KeyResult::Number(id) if id==old)
    );
    credentials.uid = 999;
    credentials.fsuid = 999;
    memory.write(0x2ff8, b"replaced").unwrap();
    page.finish();
    let id = call.check(&mut memory).unwrap().unwrap();
    assert_ne!(id, old);
    let original_credentials = Credentials::user(1000, 2000);
    assert_eq!(
        description(&keys, &registry, &original_credentials, id as i32),
        b"keyring;1000;2000;3f130000;original\0"
    );
    let later = keys
        .join(&registry, &original_credentials, Some(b"later".to_vec()))
        .unwrap();
    assert_eq!(call.check(&mut memory), Some(Ok(id)));
    assert!(
        matches!(keys.access(&registry,&original_credentials,-3,KeyOperation::Lookup(false)).unwrap(),KeyResult::Number(value) if value==later)
    );
}
#[test]
fn key_description_holds_original_key_until_copy_success_error_or_cancel() {
    for mode in 0..3 {
        let (mut memory, page) = memory();
        let keys = SessionKeys::default();
        let registry = Arc::new(KeyRegistry::default());
        let credentials = Credentials::user(1000, 2000);
        let id = keys
            .join(&registry, &credentials, Some(b"before".to_vec()))
            .unwrap();
        let expected = description(&keys, &registry, &credentials, id as i32);
        let mut call = TaskCopyCall::keys(
            keys.clone(),
            registry.clone(),
            credentials.clone(),
            [6, id, 0x2ff8, 4096, 0, 0],
        );
        assert_eq!(call.check(&mut memory), None);
        keys.join(&registry, &credentials, Some(b"later".to_vec()))
            .unwrap();
        let observer = SessionKeys::default();
        assert!(observer
            .access(&registry, &credentials, id as i32, KeyOperation::Describe)
            .is_ok());
        memory.write(0x2ff8, &[0x77; 8]).unwrap();
        if mode == 1 {
            memory.unmap(0x3000, PAGE_SIZE).unwrap();
        }
        if mode == 2 {
            call.cancel();
        }
        page.finish();
        assert_eq!(
            call.check(&mut memory),
            Some(match mode {
                1 => Err(Errno(14)),
                2 => Err(Errno(4)),
                _ => Ok(expected.len() as u64),
            })
        );
        assert_eq!(memory.read_array::<8>(0x2ff8).unwrap(), [0x77; 8]);
        if mode == 0 {
            let mut bytes = vec![0; expected.len() - 8];
            memory.read(0x3000, &mut bytes).unwrap();
            assert_eq!(bytes, expected[8..]);
        }
        assert!(matches!(
            observer.access(&registry, &credentials, id as i32, KeyOperation::Describe),
            Err(Errno(126))
        ));
    }
}
#[test]
fn key_description_keeps_permission_snapshot_and_short_buffers_do_not_touch_pointer() {
    let (mut memory, page) = memory();
    let keys = SessionKeys::default();
    let registry = Arc::new(KeyRegistry::default());
    let credentials = Credentials::user(1000, 2000);
    let id = keys
        .join(&registry, &credentials, Some(b"before".to_vec()))
        .unwrap();
    let expected = description(&keys, &registry, &credentials, id as i32);
    let mut call = TaskCopyCall::keys(
        keys.clone(),
        registry.clone(),
        credentials.clone(),
        [6, id, 0x2ff8, 4096, 0, 0],
    );
    assert_eq!(call.check(&mut memory), None);
    keys.access(
        &registry,
        &credentials,
        id as i32,
        KeyOperation::SetPermissions(0x3f3f0000),
    )
    .unwrap();
    page.finish();
    assert_eq!(call.check(&mut memory), Some(Ok(expected.len() as u64)));
    let mut bytes = vec![0; expected.len()];
    memory.read(0x2ff8, &mut bytes).unwrap();
    assert_eq!(bytes, expected);
    for args in [
        [6, id, 0x90000, 1 | (1u64 << 32), 0, 0],
        [6, id, 0, 4096, 0, 0],
    ] {
        assert_eq!(
            TaskCopyCall::keys(keys.clone(), registry.clone(), credentials.clone(), args)
                .check(&mut memory),
            Some(Ok(expected.len() as u64))
        );
    }
}
#[test]
fn key_name_validation_and_cancel_precede_selection_and_unsupported_ops_skip_memory() {
    let (mut memory, page) = memory();
    let keys = SessionKeys::default();
    let registry = Arc::new(KeyRegistry::default());
    let credentials = Credentials::default();
    let old = keys
        .join(&registry, &credentials, Some(b"before".to_vec()))
        .unwrap();
    memory.write(0x2ff8, b"original").unwrap();
    let mut call = TaskCopyCall::keys(
        keys.clone(),
        registry.clone(),
        credentials.clone(),
        [1, 0x2ff8, 0, 0, 0, 0],
    );
    assert_eq!(call.check(&mut memory), None);
    call.cancel();
    page.finish();
    assert_eq!(call.check(&mut memory), Some(Err(Errno(4))));
    memory.write(0x1000, &vec![b'x'; 4096]).unwrap();
    memory.write(0x2100, b".hidden\0").unwrap();
    memory.write(0x2200, b"\0").unwrap();
    for (args, error) in [
        ([1, 0x1000, 0, 0, 0, 0], 22),
        ([1, 0x2100, 0, 0, 0, 0], 1),
        ([1, 0x2200, 0, 0, 0, 0], 22),
        ([1, 0x90000, 0, 0, 0, 0], 14),
        ([99, 0x90000, 0x90000, 4096, 0, 0], 95),
    ] {
        assert_eq!(
            TaskCopyCall::keys(keys.clone(), registry.clone(), credentials.clone(), args)
                .check(&mut memory),
            Some(Err(Errno(error)))
        );
    }
    assert!(
        matches!(keys.access(&registry,&credentials,-3,KeyOperation::Lookup(false)).unwrap(),KeyResult::Number(id) if id==old)
    );
}
#[test]
fn task_scalar_output_is_one_original_store_even_when_crossing_a_lazy_page() {
    let (mut memory, page) = memory();
    memory.write(0x2ffe, &[0x77; 2]).unwrap();
    let mut call = TaskCopyCall::scalar(0x2ffe, 17);
    assert_eq!(call.check(&mut memory), None);
    assert_eq!(memory.read_array::<2>(0x2ffe).unwrap(), [0x77; 2]);
    page.finish();
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
    assert_eq!(memory.read_array::<4>(0x2ffe).unwrap(), 17u32.to_le_bytes());
    memory.write_array(0x2ffe, 19u32.to_le_bytes()).unwrap();
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
    assert_eq!(memory.read_array::<4>(0x2ffe).unwrap(), 19u32.to_le_bytes());
}
#[test]
fn bare_dispatch_keeps_original_registers_and_metadata_owner_until_handoff_or_resume() {
    for handoff in [false, true] {
        let (mut memory, page) = memory();
        let mut linux = crate::Linux::new(0x10000);
        linux.command_name.set(b"before");
        memory.write(0x2ff8, b"original").unwrap();
        let mut cpu = trames_execution::Aarch64State::default();
        cpu.registers[..6].copy_from_slice(&[15, 0x2ff8, 0, 0, 0, 0]);
        cpu.registers[8] = 167;
        let original = cpu.clone();
        let mut output = crate::CapturedOutput::default();
        assert_eq!(
            linux.dispatch_task_untraced(7, &mut cpu, &mut memory, &mut output),
            crate::SyscallOutcome::Deferred
        );
        assert_eq!(cpu, original);
        assert!(linux.task_copy_fault(7).is_some());
        assert_eq!(linux.command_name.get(), b"before");
        memory.write(0x2ff8, b"replaced").unwrap();
        if handoff {
            let name = linux.command_name.clone();
            let mut call = linux.take_task_copy(7).unwrap();
            drop(linux);
            page.finish();
            assert_eq!(call.check(&mut memory), Some(Ok(0)));
            assert_eq!(name.get(), b"original");
        } else {
            page.finish();
            assert_eq!(
                linux.dispatch_task_untraced(7, &mut cpu, &mut memory, &mut output),
                crate::SyscallOutcome::Continue
            );
            assert_eq!(cpu.registers[0], 0);
            assert_eq!(linux.command_name.get(), b"original");
            assert!(linux.take_task_copy(7).is_none());
        }
    }
}
#[test]
fn bare_exit_releases_original_key_copy_and_group_exit_cancels_other_metadata_calls() {
    for group in [false, true] {
        let (mut memory, _page) = memory();
        let mut linux = crate::Linux::new(0x10000);
        let keys = linux.session_keys.clone();
        let registry = linux.vfs.key_registry();
        let credentials = linux.vfs.credentials.clone();
        let id = keys
            .join(&registry, &credentials, Some(b"original".to_vec()))
            .unwrap();
        let mut cpu = trames_execution::Aarch64State::default();
        cpu.registers[..6].copy_from_slice(&[6, id, 0x2ff8, 4096, 0, 0]);
        cpu.registers[8] = 219;
        let mut output = crate::CapturedOutput::default();
        assert_eq!(
            linux.dispatch_task_untraced(7, &mut cpu, &mut memory, &mut output),
            crate::SyscallOutcome::Deferred
        );
        keys.join(&registry, &credentials, Some(b"later".to_vec()))
            .unwrap();
        let observer = SessionKeys::default();
        assert!(observer
            .access(&registry, &credentials, id as i32, KeyOperation::Describe)
            .is_ok());
        cpu.registers[..6].copy_from_slice(&[16, 0x3000, 0, 0, 0, 0]);
        cpu.registers[8] = 167;
        assert_eq!(
            linux.dispatch_task_untraced(8, &mut cpu, &mut memory, &mut output),
            crate::SyscallOutcome::Deferred
        );
        cpu.registers[0] = 0;
        cpu.registers[8] = if group { 94 } else { 93 };
        assert_eq!(
            linux.dispatch_task_untraced(7, &mut cpu, &mut memory, &mut output),
            crate::SyscallOutcome::Exit(0)
        );
        assert!(linux.take_task_copy(7).is_none());
        assert_eq!(linux.take_task_copy(8).is_none(), group);
        assert!(matches!(
            observer.access(&registry, &credentials, id as i32, KeyOperation::Describe),
            Err(Errno(126))
        ));
    }
}
