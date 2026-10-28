// SPDX-License-Identifier: GPL-3.0-or-later
//! Sole-executor private bytes: CPU/native equivalence and admission boundaries.
use super::*;

fn owned() -> Memory {
    let mut memory = Memory::default();
    memory.map(0x40000, 8 * PAGE_SIZE, Permissions::RW).unwrap();
    memory
}
fn locks(view: &View) -> u64 {
    view.snapshot
        .frames
        .iter()
        .filter_map(|f| f.bytes.mutable())
        .map(|p| p.acquisitions())
        .sum()
}
fn admit(view: &mut View) {
    // SAFETY: these tests keep the source and all peer Views quiescent for this
    // VM's private bytes. Only explicitly shared storage is used concurrently.
    assert!(unsafe { view.try_exclusive_private() });
}

#[test]
fn private_cpu_native_and_exclusives_skip_locks_and_publish_on_handoff() {
    let mut memory = owned();
    memory.protect(0x44000, PAGE_SIZE, Permissions::R).unwrap();
    memory
        .protect(
            0x47000,
            PAGE_SIZE,
            Permissions {
                execute: true,
                ..Permissions::RW
            },
        )
        .unwrap();
    let mut registry = Registry::default();
    let mut view = memory.parallel_view(&mut registry).unwrap();
    admit(&mut view);
    let before = locks(&view);
    for width in [1, 2, 4, 8, 16] {
        let value = [width as u8; 16];
        view.write(0x40040, &value[..width]).unwrap();
        let mut result = [0; 16];
        view.read(0x40040, &mut result[..width]).unwrap();
        assert_eq!(&result[..width], &value[..width]);
    }
    // Exercise protected scalar aliases when host granules allow them, and
    // software fragments crossing guest-page and mixed-permission boundaries.
    view.write_array(0x40080, 73u64.to_le_bytes()).unwrap();
    assert_eq!(
        view.native_read_array::<8>(0x40080).unwrap(),
        73u64.to_le_bytes()
    );
    view.write(0x40ffc, &[17; 16]).unwrap();
    assert_eq!(view.read_array::<16>(0x40ffc).unwrap(), [17; 16]);
    let mut bytes = [0; 8];
    let old = view.exclusive_read(0x40000, &mut bytes).unwrap();
    view.write_array(0x40000, [1; 8]).unwrap();
    view.write_array(0x40000, [0; 8]).unwrap();
    assert!(!view.exclusive_write(0x40000, &[2; 8], Some(old)).unwrap());
    let neighbor = view.exclusive_read(0x40010, &mut bytes).unwrap();
    view.fill_with(0x40000, 8, |b| b.fill(3)).unwrap();
    assert!(view
        .exclusive_write(0x40010, &[4; 8], Some(neighbor))
        .unwrap());
    view.atomic_update(0x40020, 8, |b| {
        b.fill(5);
        ((), true)
    })
    .unwrap();
    view.fill_with(0x42000, PAGE_SIZE as usize, |b| b.fill(42))
        .unwrap();
    view.copy_with(0x43000, 0x42000, PAGE_SIZE as usize, |d, s| {
        d.copy_from_slice(s)
    })
    .unwrap();
    assert!(
        view.with_read_pair(0x42000, 0x43000, 4096, |a, b| a == b)
            .unwrap()
            .0
    );
    view.copy_with(0x42001, 0x42000, 4095, |d, s| d.copy_from_slice(s))
        .unwrap();
    assert!(
        view.with_read_pair(0x42000, 0x42001, 4095, |a, b| a == b)
            .unwrap()
            .0
    );
    let code = view.instruction_page_identity(0x47000).unwrap();
    view.write_array(0x47000, 0xd503201fu32.to_le_bytes())
        .unwrap();
    assert_eq!(view.fetch_u32(0x47000).unwrap(), 0xd503201f);
    assert_ne!(view.instruction_page_identity(0x47000).unwrap(), code);
    assert!(matches!(
        view.write(0x43fff, &[1, 2]),
        Err(MemoryError::Permission { .. })
    ));
    assert_eq!(view.read_array::<1>(0x43fff).unwrap(), [42]);
    assert_eq!(
        locks(&view),
        before,
        "CPU and native private access must both skip region RMWs"
    );
    // Move the same View to a ready-I/O service actor, then return ownership.
    let view = std::thread::spawn(move || {
        view.fill_with(0x45000, 4096, |b| b.fill(93)).unwrap();
        view
    })
    .join()
    .unwrap();
    assert_eq!(locks(&view), before);
    drop(view);
    memory.commit_parallel().unwrap();
    assert_eq!(memory.read_array::<8>(0x40000).unwrap(), [3; 8]);
    assert_eq!(memory.read_array::<8>(0x40010).unwrap(), [4; 8]);
    assert_eq!(memory.read_array::<8>(0x45000).unwrap(), [93; 8]);
    assert_eq!(memory.fetch_u32(0x47000).unwrap(), 0xd503201f);
}

#[test]
fn all_snapshot_generations_count_towards_admission_and_clones_start_guarded() {
    let mut memory = owned();
    let mut registry = Registry::default();
    let old = memory.parallel_view(&mut registry).unwrap();
    backing::backing_changed();
    let mut next = memory.parallel_view(&mut registry).unwrap();
    // SAFETY: no byte access is concurrent; the attempted admission must fail.
    assert!(!unsafe { next.try_exclusive_private() });
    drop(old);
    let clone = next.clone();
    assert!(!clone.exclusive_private_enabled());
    // SAFETY: no private access is in progress; a live clone rejects admission.
    assert!(!unsafe { next.try_exclusive_private() });
    drop(clone);
    admit(&mut next);
    assert!(next.exclusive_private_enabled());
}

#[test]
fn shared_backings_remain_atomic_across_private_vm_epochs() {
    let mut parent = owned();
    parent
        .map_shared_anonymous(0x50000, PAGE_SIZE, Permissions::RW, false)
        .unwrap();
    let mut child = parent.clone();
    let mut registry = Registry::default();
    let mut a = parent.parallel_view(&mut registry).unwrap();
    let mut b = child.parallel_view(&mut registry).unwrap();
    for view in [&mut a, &mut b] {
        admit(view);
        assert!(
            view.frame(0x40000, Access::Write).unwrap().private_access
                & PrivateMode::Exclusive as u8
                != 0
        );
        assert_eq!(
            view.frame(0x50000, Access::Write).unwrap().private_access
                & PrivateMode::Exclusive as u8,
            0
        );
    }
    let gate = Arc::new(std::sync::Barrier::new(2));
    let joins: Vec<_> = [a, b]
        .into_iter()
        .enumerate()
        .map(|(rank, mut view)| {
            let gate = gate.clone();
            std::thread::spawn(move || {
                view.read_array::<8>(0x50000).unwrap();
                let private = view
                    .frame(0x40000, Access::Write)
                    .unwrap()
                    .bytes
                    .mutable()
                    .unwrap()
                    .clone();
                let shared = view
                    .frame(0x50000, Access::Write)
                    .unwrap()
                    .bytes
                    .mutable()
                    .unwrap()
                    .clone();
                let (p, s) = (private.acquisitions(), shared.acquisitions());
                gate.wait();
                for _ in 0..1000 {
                    view.atomic_update(0x50000, 8, |b| {
                        let n = u64::from_le_bytes(b.try_into().unwrap()) + 1;
                        b.copy_from_slice(&n.to_le_bytes());
                        ((), true)
                    })
                    .unwrap();
                    view.write_array(0x40000, (rank as u64 + 1).to_le_bytes())
                        .unwrap();
                }
                assert_eq!(private.acquisitions(), p);
                assert!(shared.acquisitions() > s);
            })
        })
        .collect();
    for join in joins {
        join.join().unwrap();
    }
    parent.commit_parallel().unwrap();
    child.commit_parallel().unwrap();
    assert_eq!(parent.read_u64(0x50000).unwrap(), 2000);
    assert_eq!(parent.read_u64(0x40000).unwrap(), 1);
    assert_eq!(child.read_u64(0x40000).unwrap(), 2);
}

#[test]
fn retained_readonly_fork_storage_is_not_mistaken_for_unique_bytes() {
    let mut parent = owned();
    parent.write_array(0x40000, [7; 8]).unwrap();
    parent.protect(0x40000, PAGE_SIZE, Permissions::R).unwrap();
    let mut registry = Registry::default();
    drop(parent.parallel_view(&mut registry).unwrap());
    let mut child = parent.clone();
    let parent_view = parent.parallel_view(&mut registry).unwrap();
    drop(parent);
    // The coordinate Rc now has only one owner, but the other VM's View still
    // owns this physical page. The Arc check must reject its unlocked guard.
    let mut child_view = child.parallel_view(&mut registry).unwrap();
    admit(&mut child_view);
    let frame = child_view.frame(0x40000, Access::Read).unwrap();
    assert_eq!(frame.private_access & PrivateMode::Exclusive as u8, 0);
    assert!(!child_view.frame_guard(frame, 0, 8).is_exclusive());
    assert_eq!(child_view.read_array::<8>(0x40000).unwrap(), [7; 8]);
    assert_eq!(parent_view.read_array::<8>(0x40000).unwrap(), [7; 8]);
}

#[test]
fn pin_registration_invalidates_cached_private_ownership_without_rebuilding_other_pages() {
    let mut memory = owned();
    // A former registration leaves stable heap storage behind. Registering it
    // again changes ownership without changing its allocation or permissions.
    drop(memory.pin_rw(0x40000, 8).unwrap());
    let mut registry = Registry::default();
    let mut before = memory.parallel_view(&mut registry).unwrap();
    admit(&mut before);
    assert!(before
        .frame_guard(before.frame(0x40000, Access::Read).unwrap(), 0, 8)
        .is_exclusive());
    drop(before);

    let pin = memory.pin_rw(0x40000, 8).unwrap();
    let mut view = memory.parallel_view(&mut registry).unwrap();
    admit(&mut view);
    let frame = view.frame(0x40000, Access::Read).unwrap();
    assert_eq!(frame.private_access, 0);
    assert!(!view.frame_guard(frame, 0, 8).is_exclusive());
    let neighbor = view.frame(0x41000, Access::Write).unwrap();
    assert!(view.frame_guard(neighbor, 0, 8).is_exclusive());
    pin.write(0, &[42; 8]).unwrap();
    assert_eq!(view.read_array::<8>(0x40000).unwrap(), [42; 8]);
    assert_eq!(registry.metrics.full_rebuilds, 1);
    assert_eq!(registry.metrics.incremental_pages, 1);
    drop(view);

    // A protected VA is still writable through its registration. Read-only
    // epoch admission must not expose an unlocked Rust read beside that pin.
    memory.protect(0x40000, PAGE_SIZE, Permissions::R).unwrap();
    let mut a = memory.parallel_view(&mut registry).unwrap();
    let mut b = a.clone();
    // SAFETY: these are every View of this VM; its source stays quiescent.
    assert!(unsafe { View::try_private_epoch(&mut [&mut a, &mut b]) });
    let frame = a.frame(0x40000, Access::Read).unwrap();
    assert_eq!(frame.private_access, 0);
    assert!(!a.frame_guard(frame, 0, 8).is_exclusive());
    std::thread::spawn(move || pin.write(0, &[73; 8]).unwrap())
        .join()
        .unwrap();
    assert_eq!(a.read_array::<8>(0x40000).unwrap(), [73; 8]);
}

#[test]
fn native_unwind_ends_private_borrows_and_keeps_dirty_and_monitor_effects() {
    let mut memory = owned();
    let mut registry = Registry::default();
    let mut view = memory.parallel_view(&mut registry).unwrap();
    admit(&mut view);
    let mut old = [0; 8];
    let token = view.exclusive_read(0x40000, &mut old).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        view.fill_with(0x40000, 8, |b| {
            b.fill(19);
            panic!("native unwind");
        })
        .unwrap();
    }));
    assert!(result.is_err());
    assert!(!view
        .exclusive_write(0x40000, &[20; 8], Some(token))
        .unwrap());
    assert_eq!(view.read_array::<8>(0x40000).unwrap(), [19; 8]);
    drop(view);
    memory.commit_parallel().unwrap();
    assert_eq!(memory.read_array::<8>(0x40000).unwrap(), [19; 8]);
}
