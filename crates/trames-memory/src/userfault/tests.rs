// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
#[test]
fn an_unregistered_or_closed_probe_does_not_lock_ordinary_memory_accesses() {
    let mut memory = memory();
    let file = memory.userfaultfd(true);
    file.initialize().unwrap();
    assert!(!memory.async_faults_possible());
    let faults = file.faults.clone();
    {
        let _state = faults.0.lock().unwrap();
        assert!(UserAccessScope::for_memory(&memory).is_none());
        assert_eq!(memory.read_array::<1>(0x10000).unwrap(), [0]);
    }
    finish(&mut memory, file.register(0x10000, PAGE_SIZE).unwrap());
    assert!(memory.userfaults_active());
    assert!(memory.async_faults_possible());
    drop(file);
    let _state = faults.0.lock().unwrap();
    assert!(!memory.userfaults_active());
    assert_eq!(memory.read_array::<1>(0x10000).unwrap(), [0]);
}
fn memory() -> Memory {
    let mut memory = Memory::default();
    memory
        .map(0x10000, PAGE_SIZE * 32, Permissions::RW)
        .unwrap();
    memory.memory_report().bind_read_waker(Arc::new(|_| {}));
    memory
}
fn finish(memory: &mut Memory, request: Arc<MmControl>) -> Vec<u8> {
    assert!(memory.activate_proc_reads());
    request.result().expect("checkpoint completion").unwrap()
}
fn pending(error: MemoryError) -> PageFault {
    let MemoryError::Pending(fault) = error else {
        panic!("expected missing fault, got {error:?}")
    };
    fault
}
#[test]
fn original_views_copy_dontwake_and_zero_page_share_real_storage() {
    let mut memory = memory();
    let file = memory.userfaultfd(false);
    assert_eq!(file.poll(1, true).0, 8);
    assert_eq!(file.read(32), Err(22));
    file.initialize().unwrap();
    finish(&mut memory, file.register(0x10000, PAGE_SIZE * 32).unwrap());
    let mut registry = parallel::Registry::default();
    let mut view = memory.parallel_view(&mut registry).unwrap();
    let fault = pending(view.write(0x11007, b"first").unwrap_err());
    let second = pending(view.read_array::<1>(0x11008).unwrap_err());
    assert!(!Arc::ptr_eq(&fault.wait, &second.wait));
    assert_eq!(file.poll(1, true).0, 1);
    let msg = file.read(32).unwrap();
    assert_eq!(msg[0], 0x12);
    assert_eq!(u64::from_le_bytes(msg[8..16].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(msg[16..24].try_into().unwrap()), 0x11000);
    let read_msg = file.read(32).unwrap();
    assert_eq!(u64::from_le_bytes(read_msg[8..16].try_into().unwrap()), 0);
    drop(view);
    finish(
        &mut memory,
        file.fill(0x11000, Some(vec![42; PAGE_SIZE as usize]), false)
            .unwrap(),
    );
    assert!(!fault.wait.ready());
    assert!(!second.wait.ready());
    assert_eq!(memory.read_array::<1>(0x11007).unwrap(), [42]);
    file.wake(0x11000, PAGE_SIZE).unwrap();
    assert!(fault.wait.ready());
    assert!(second.wait.ready());
    let zero = pending(memory.read_array::<1>(0x12000).unwrap_err());
    let resident = memory.resident_bytes();
    finish(&mut memory, file.fill(0x12000, None, true).unwrap());
    assert!(zero.wait.ready());
    assert_eq!(memory.read_array::<1>(0x12000).unwrap(), [0]);
    assert_eq!(
        memory.resident_bytes(),
        resident,
        "zero PTE does not charge a physical page"
    );
    assert_eq!(memory.resident(0x12000, PAGE_SIZE).unwrap(), [1]);
    memory.write(0x12000, b"z").unwrap();
    assert_eq!(memory.resident_bytes(), resident + PAGE_SIZE as usize);
}
#[test]
fn cancellation_last_close_unmap_and_original_mm_retirement_never_leave_a_fault_parked() {
    for action in 0..4 {
        let mut memory = memory();
        let file = memory.userfaultfd(false);
        file.initialize().unwrap();
        finish(&mut memory, file.register(0x10000, PAGE_SIZE * 32).unwrap());
        let fault = pending(memory.read_array::<1>(0x13000).unwrap_err());
        if action == 0 {
            drop(fault);
            assert_eq!(file.poll(1, true).0, 0);
            assert_eq!(file.read(32), Err(11));
        } else {
            match action {
                1 => drop(file),
                2 => memory.unmap(0x13000, PAGE_SIZE).unwrap(),
                _ => memory.retire_memory_report(),
            }
            assert!(fault.wait.ready());
        }
    }
}
#[test]
fn fork_unregistered_remap_and_discard_keep_linux_missing_boundaries() {
    let mut memory = memory();
    memory.write(0x10000, b"present").unwrap();
    assert_eq!(memory.read_array::<1>(0x15000).unwrap(), [0]);
    let file = memory.userfaultfd(false);
    file.initialize().unwrap();
    finish(&mut memory, file.register(0x10000, PAGE_SIZE * 32).unwrap());
    assert_eq!(memory.read_array::<7>(0x10000).unwrap(), *b"present");
    assert_eq!(memory.read_array::<1>(0x15000).unwrap(), [0]);
    let mut child = memory.clone();
    child.write(0x11000, b"child").unwrap();
    assert_eq!(file.poll(1, true).0, 0);
    assert_eq!(memory.read_array::<7>(0x10000).unwrap(), *b"present");
    let fault = pending(memory.read_array::<1>(0x11000).unwrap_err());
    memory
        .remap(0x10000, PAGE_SIZE * 32, 0x10000, PAGE_SIZE * 33, false)
        .unwrap();
    assert!(fault.wait.ready());
    let extension = pending(memory.read_array::<1>(0x30000).unwrap_err());
    memory.unmap(0x30000, PAGE_SIZE).unwrap();
    assert!(extension.wait.ready());
    memory.discard(0x10000, PAGE_SIZE).unwrap();
    let missing = pending(memory.read_array::<1>(0x10000).unwrap_err());
    finish(&mut memory, file.unregister(0x10000, PAGE_SIZE).unwrap());
    assert!(missing.wait.ready());
    assert_eq!(memory.read_array::<1>(0x10000).unwrap(), [0]);
    memory
        .remap(0x10000, PAGE_SIZE * 32, 0x50000, PAGE_SIZE * 32, false)
        .unwrap();
    assert_eq!(memory.read_array::<1>(0x51000).unwrap(), [0]);
}
#[test]
fn user_only_rejects_kernel_copies_and_shared_mm_preserves_original_registration() {
    let mut memory = memory();
    let file = memory.userfaultfd(true);
    file.initialize().unwrap();
    finish(&mut memory, file.register(0x10000, PAGE_SIZE * 32).unwrap());
    assert_eq!(
        memory.read_array::<1>(0x11000),
        Err(MemoryError::Bus(0x11000))
    );
    assert_eq!(file.poll(1, true).0, 0);
    let peer = memory.share();
    let fault = {
        let _user = UserAccessScope::for_memory(&peer)
            .expect("original shared mm enables user-only faults");
        pending(peer.read_array::<1>(0x11000).unwrap_err())
    };
    finish(
        &mut memory,
        file.fill(0x11000, Some(vec![9; PAGE_SIZE as usize]), true)
            .unwrap(),
    );
    assert!(fault.wait.ready());
    assert_eq!(peer.read_array::<1>(0x11000).unwrap(), [9]);
}

#[test]
fn unregister_capability_covers_other_contexts_in_the_original_mm() {
    let mut memory = memory();
    let owner = memory.userfaultfd(false);
    let other = memory.userfaultfd(false);
    owner.initialize().unwrap();
    other.initialize().unwrap();
    finish(
        &mut memory,
        owner.register(0x10000, PAGE_SIZE * 32).unwrap(),
    );
    let missing = pending(memory.read_array::<1>(0x11000).unwrap_err());
    // Linux's unregister is scoped to the fd's mm, not the context that
    // previously registered each VMA. Closing other still affects only its own.
    finish(&mut memory, other.unregister(0x11000, PAGE_SIZE).unwrap());
    assert!(missing.wait.ready());
    assert_eq!(memory.read_array::<1>(0x11000).unwrap(), [0]);
    let missing = pending(memory.read_array::<1>(0x12000).unwrap_err());
    drop(other);
    assert!(!missing.wait.ready());
    drop(owner);
    assert!(missing.wait.ready());
}

#[test]
fn eager_copy_follows_migration_while_an_accepted_fault_keeps_its_original_owner() {
    let mut memory = memory();
    let first = MemoryCgroup::new(None);
    let second = MemoryCgroup::new(None);
    let actor = Arc::new(CgroupMemoryTarget::default());
    actor.set(Some(first.clone()));
    let file = {
        let _scope = actor.scope();
        let accepted = CgroupMemoryContext::capture();
        let _accepted = accepted.enter();
        memory.userfaultfd(false)
    };
    file.initialize().unwrap();
    finish(&mut memory, file.register(0x10000, PAGE_SIZE * 32).unwrap());
    actor.set(Some(second.clone()));
    finish(
        &mut memory,
        file.fill(0x10000, Some(vec![1; PAGE_SIZE as usize]), true)
            .unwrap(),
    );
    assert_eq!(first.current(), 0);
    assert_eq!(second.current(), PAGE_SIZE as usize);
    actor.set(Some(first.clone()));
    let fault = {
        let _scope = actor.scope();
        pending(memory.read_array::<1>(0x11000).unwrap_err())
    };
    actor.set(Some(second.clone()));
    finish(
        &mut memory,
        file.fill(0x11000, Some(vec![2; PAGE_SIZE as usize]), true)
            .unwrap(),
    );
    assert!(fault.wait.ready());
    assert_eq!(first.current(), PAGE_SIZE as usize);
    assert_eq!(second.current(), PAGE_SIZE as usize);
}
