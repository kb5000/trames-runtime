// SPDX-License-Identifier: GPL-3.0-or-later
//! Immutable private pages shared by CPUs of the same frozen VM.
use super::*;

fn memory() -> Memory {
    let mut memory = Memory::default();
    memory
        .map(0x40000, 16 * PAGE_SIZE, Permissions::RW)
        .unwrap();
    memory
        .fill_with(0x40000, 16 * PAGE_SIZE as usize, |b| b.fill(0x37))
        .unwrap();
    memory
        .write_array(0x40000, 0xd503201fu32.to_le_bytes())
        .unwrap();
    memory.write_array(0x4f000, 0u64.to_le_bytes()).unwrap();
    memory
        .protect(0x40000, 4 * PAGE_SIZE, Permissions::RX)
        .unwrap();
    memory
        .protect(0x44000, 4 * PAGE_SIZE, Permissions::R)
        .unwrap();
    memory
}
fn views(memory: &mut Memory, registry: &mut Registry, count: usize) -> Vec<View> {
    let mut views = vec![memory.parallel_view(registry).unwrap()];
    for _ in 1..count {
        views.push(views[0].clone());
    }
    views
}
fn admit(views: &mut [View]) -> bool {
    // SAFETY: test sources stay quiescent until every admitted View is dropped.
    // All live VM Views belong to this slice; no mapping/source callback runs.
    unsafe { View::try_private_epoch(&mut views.iter_mut().collect::<Vec<_>>()) }
}
fn storage(view: &View, at: u64) -> Arc<SharedPage> {
    view.frame(at, Access::Read)
        .unwrap()
        .bytes
        .bytes
        .as_ref()
        .unwrap()
        .clone()
}

#[test]
fn concurrent_cpu_native_reads_and_monitors_need_no_region_lock_but_rw_stays_atomic() {
    let mut source = memory();
    let mut registry = Registry::default();
    let mut readers = views(&mut source, &mut registry, 4);
    assert!(admit(&mut readers));
    assert!(readers.iter().all(View::readonly_private_enabled));
    let code = storage(&readers[0], 0x40000);
    let data = storage(&readers[0], 0x44000);
    let writable = storage(&readers[0], 0x4f000);
    let counts = (
        code.acquisitions(),
        data.acquisitions(),
        writable.acquisitions(),
    );
    let (ready, received) = std::sync::mpsc::channel();
    let mut release = Vec::new();
    let mut joins = Vec::new();
    for (rank, mut view) in readers.into_iter().enumerate() {
        let ready = ready.clone();
        let (go, start) = std::sync::mpsc::channel();
        release.push(go);
        joins.push(std::thread::spawn(move || {
            // All four readers hold slices of the very same bytes at once.
            // Timeout-bounded channels catch accidentally serialized borrows.
            view.with_read_chunk(0x44000, 4096, |bytes| {
                ready.send(rank).unwrap();
                start
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                assert!(bytes.iter().all(|&b| b == 0x37));
                // Reentrant immutable reads need no recursive region lock.
                assert_eq!(view.read_array::<8>(0x44000).unwrap(), [0x37; 8]);
            })
            .unwrap();
            let mut bytes = [0; 8];
            let token = view.exclusive_read(0x44000, &mut bytes).unwrap();
            for _ in 0..1000 {
                assert_eq!(view.read_array::<16>(0x44000).unwrap(), [0x37; 16]);
                assert_eq!(view.native_read_array::<8>(0x44000).unwrap(), [0x37; 8]);
                assert_eq!(view.fetch_u32(0x40000).unwrap(), 0xd503201f);
                assert!(
                    view.with_read_pair(0x44000, 0x44040, 64, |a, b| a == b)
                        .unwrap()
                        .0
                );
                assert_eq!(view.exclusive_read(0x44000, &mut bytes).unwrap(), token);
                // The source is immutable; each destination is still a normal
                // RW region. A shared counter exercises the original RMW domain.
                view.copy_with(0x48000 + rank as u64 * 64, 0x44000, 64, |d, s| {
                    d.copy_from_slice(s)
                })
                .unwrap();
                view.atomic_update(0x4f000, 8, |b| {
                    let n = u64::from_le_bytes(b.try_into().unwrap()) + 1;
                    b.copy_from_slice(&n.to_le_bytes());
                    ((), true)
                })
                .unwrap();
            }
            assert!(matches!(
                view.write_array(0x44000, [0; 8]),
                Err(MemoryError::Permission { .. })
            ));
            assert!(matches!(
                view.atomic_update::<()>(0x44000, 8, |_| panic!("must reject mutation")),
                Err(MemoryError::Permission { .. })
            ));
            assert!(matches!(
                view.exclusive_write(0x44000, &[0; 8], Some(token)),
                Err(MemoryError::Permission { .. })
            ));
            token
        }));
    }
    for _ in 0..4 {
        received
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
    }
    for go in release {
        go.send(()).unwrap();
    }
    let tokens: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
    assert!(tokens.iter().all(|&token| token == tokens[0]));
    assert_eq!(code.acquisitions(), counts.0);
    assert_eq!(data.acquisitions(), counts.1);
    assert!(writable.acquisitions() > counts.2);
    source.commit_parallel().unwrap();
    assert_eq!(source.read_u64(0x4f000).unwrap(), 4000);
    assert_eq!(source.read_array::<8>(0x44000).unwrap(), [0x37; 8]);
}

#[test]
fn admission_rejects_missing_external_or_mismatched_snapshot_views() {
    let mut source = memory();
    let mut registry = Registry::default();
    let mut readers = views(&mut source, &mut registry, 2);
    assert!(!admit(&mut readers[..1]));
    let external = readers[0].clone();
    assert!(!admit(&mut readers));
    drop(external);
    assert!(admit(&mut readers));
    drop(readers);
    // Two live generations of one VM have the same total user count, but only
    // identical frozen mappings can establish the no-writer permission proof.
    let old = source.parallel_view(&mut registry).unwrap();
    backing::backing_changed();
    let next = source.parallel_view(&mut registry).unwrap();
    let mut mixed = [old, next];
    assert!(!admit(&mut mixed));
    assert!(mixed
        .iter()
        .all(|v| !v.readonly_private_enabled() && !v.exclusive_private_enabled()));
}

#[test]
fn readonly_epochs_keep_shared_backing_and_retained_fork_pages_guarded() {
    let mut source = memory();
    source
        .map_shared_anonymous(0x50000, PAGE_SIZE, Permissions::R, false)
        .unwrap();
    let mut registry = Registry::default();
    drop(source.parallel_view(&mut registry).unwrap());
    let mut child = source.clone();
    let retained = source.parallel_view(&mut registry).unwrap();
    drop(source);
    let mut readers = views(&mut child, &mut registry, 2);
    assert!(admit(&mut readers));
    let fork = storage(&readers[0], 0x44000);
    let shared = storage(&readers[0], 0x50000);
    let before = (fork.acquisitions(), shared.acquisitions());
    for view in &readers {
        assert_eq!(view.read_array::<8>(0x44000).unwrap(), [0x37; 8]);
        assert_eq!(view.read_array::<8>(0x50000).unwrap(), [0; 8]);
    }
    assert!(fork.acquisitions() > before.0);
    assert!(shared.acquisitions() > before.1);
    assert_eq!(retained.read_array::<8>(0x44000).unwrap(), [0x37; 8]);
}

#[test]
fn readonly_native_unwind_and_joined_permission_changes_preserve_monitor_lifetimes() {
    let mut source = memory();
    let mut registry = Registry::default();
    let mut readers = views(&mut source, &mut registry, 2);
    assert!(admit(&mut readers));
    let mut bytes = [0; 8];
    let token = readers[0].exclusive_read(0x44000, &mut bytes).unwrap();
    let neighbor = readers[1].exclusive_read(0x44010, &mut bytes).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        readers[0]
            .with_read_chunk(0x44000, 8, |_| panic!("readonly unwind"))
            .unwrap();
    }));
    assert!(result.is_err());
    assert_eq!(readers[1].read_array::<8>(0x44000).unwrap(), [0x37; 8]);
    drop(readers);
    source.commit_parallel().unwrap();
    source.protect(0x44000, PAGE_SIZE, Permissions::RW).unwrap();
    let mut writers = views(&mut source, &mut registry, 2);
    assert!(admit(&mut writers));
    let frame = writers[0].frame(0x44000, Access::Write).unwrap();
    assert_eq!(frame.private_access & PrivateMode::ReadOnly as u8, 0);
    writers[0].write_array(0x44000, [0x17; 8]).unwrap();
    assert!(!writers[1]
        .exclusive_write(0x44000, &[0x29; 8], Some(token))
        .unwrap());
    assert!(writers[1]
        .exclusive_write(0x44010, &[0x29; 8], Some(neighbor))
        .unwrap());
    drop(writers);
    source.commit_parallel().unwrap();
    assert_eq!(source.read_array::<8>(0x44000).unwrap(), [0x17; 8]);
    assert_eq!(source.read_array::<8>(0x44010).unwrap(), [0x29; 8]);
}
