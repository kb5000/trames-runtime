// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::uring::tests::{add, cq, setup, sqe};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use trames_memory::{Memory, PAGE_SIZE};

struct Wake;
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
struct Mask {
    value: AtomicU64,
    pending: AtomicBool,
    entered: AtomicUsize,
    finished: AtomicUsize,
    deferred: AtomicUsize,
}
struct Lease {
    task: Arc<Mask>,
    old: u64,
    active: AtomicBool,
}
impl trames_vfs::TemporaryMask for Lease {
    fn signal_pending(&self) -> bool {
        self.task.pending.load(Relaxed)
    }
    fn interrupted(&self) {
        if self.active.swap(false, Relaxed) {
            self.task.deferred.fetch_add(1, Relaxed);
        }
    }
    fn finish(&self) {
        if self.active.swap(false, Relaxed) {
            self.task.value.store(self.old, Relaxed);
            self.task.finished.fetch_add(1, Relaxed);
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        trames_vfs::TemporaryMask::finish(self);
    }
}
impl trames_vfs::TaskSignal for Mask {
    fn raise(&self, _: u32) {}
    fn temporary_mask(self: Arc<Self>, mask: u64) -> Option<Arc<dyn trames_vfs::TemporaryMask>> {
        self.entered.fetch_add(1, Relaxed);
        let old = self.value.swap(mask, Relaxed);
        Some(Arc::new(Lease {
            task: self,
            old,
            active: true.into(),
        }))
    }
}
fn mask() -> Arc<Mask> {
    Arc::new(Mask {
        value: 4.into(),
        pending: false.into(),
        entered: 0.into(),
        finished: 0.into(),
        deferred: 0.into(),
    })
}
fn caller(linux: &Linux, memory: &Memory, task: u32, mask: Option<Arc<Mask>>) -> DirectSyscalls {
    let mut source = DirectSyscalls::new(linux.vfs.direct_descriptors())
        .with_paths(linux.vfs.path_queries())
        .with_resources(linux.vfs.descriptor_factory())
        .with_urings(
            UringEpoch::default()
                .capture(&linux.vfs, memory.instruction_identity().0, task)
                .with_actor(linux.uring_actor_root()),
        )
        .with_clock(linux.uring_clock);
    if let Some(mask) = mask {
        source = source.with_task_signal(mask);
    }
    source
}
fn target() -> Arc<dyn IoWake> {
    Arc::new(Wake)
}
fn result(attempt: IoAttempt) -> Result<u64> {
    let IoAttempt::Complete(result) = attempt else {
        panic!("original enter must complete");
    };
    result
}
fn descriptor(memory: &mut Memory, mask: u64, size: u32, timeout: u64) {
    memory.write(0x2600, &[0; 24]).unwrap();
    memory.write_array(0x2600, mask.to_le_bytes()).unwrap();
    memory.write_array(0x2608, size.to_le_bytes()).unwrap();
    memory.write_array(0x2610, timeout.to_le_bytes()).unwrap();
}
#[test]
fn no_getevents_ignores_faulting_control_and_sq_hints_without_creating_a_wait() {
    for flags in [0u64, 2, 4, 8, 32, (1 << 32) | 8] {
        let (linux, mut memory, fd, ring) = setup(4);
        let source = caller(&linux, &memory, 7, None);
        let wake = target();
        add(&mut memory, &ring, sqe(0, 0, 101));
        assert_eq!(
            result(
                source
                    .start(
                        426,
                        [fd as u64, 1, 99, flags, 0x9000, 3],
                        &mut memory,
                        7,
                        &Arc::downgrade(&wake),
                        None
                    )
                    .unwrap()
            ),
            Ok(1)
        );
        assert_eq!(cq(&mut memory, &ring), (101, 0));
        assert!(ring.state.lock().unwrap().waits.is_empty());
    }
}
#[test]
fn partial_submission_skips_getevents_parameters_and_positive_count_wins_over_later_import_failure()
{
    for (requested, expected) in [(2u64, Ok(1)), (1, Ok(1)), (0, Err(Errno(14)))] {
        let (linux, mut memory, fd, ring) = setup(4);
        let source = caller(&linux, &memory, 7, None);
        let wake = target();
        if requested != 0 {
            add(&mut memory, &ring, sqe(0, 0, 101));
        }
        assert_eq!(
            result(
                source
                    .start(
                        426,
                        [fd as u64, requested, 1, 9, 0x9000, 24],
                        &mut memory,
                        7,
                        &Arc::downgrade(&wake),
                        None
                    )
                    .unwrap()
            ),
            expected
        );
        assert_eq!(ring.state.lock().unwrap().head, u32::from(requested != 0));
        assert_eq!(source.uring_completed(), 1);
    }
}
#[test]
fn ready_cq_skips_actual_timeout_mask_and_size_checks_and_min_complete_is_clamped() {
    let (linux, mut memory, fd, ring) = setup(2);
    let mask = mask();
    let source = caller(&linux, &memory, 7, Some(mask.clone()));
    let wake = target();
    for start in [0u64, 2] {
        add(&mut memory, &ring, sqe(0, 0, start));
        add(&mut memory, &ring, sqe(0, 0, start + 1));
        assert_eq!(
            result(
                source
                    .start(
                        426,
                        [fd as u64, 2, 0, 0, 0, 0],
                        &mut memory,
                        7,
                        &Arc::downgrade(&wake),
                        None
                    )
                    .unwrap()
            ),
            Ok(2)
        );
    }
    descriptor(&mut memory, 0x9000, 7, 0x9000);
    assert_eq!(
        result(
            source
                .start(
                    426,
                    [fd as u64, 0, u32::MAX as u64, 9, 0x2600, 24],
                    &mut memory,
                    7,
                    &Arc::downgrade(&wake),
                    None
                )
                .unwrap()
        ),
        Ok(0)
    );
    assert_eq!(mask.entered.load(Relaxed), 0);
    assert_eq!(mask.value.load(Relaxed), 4);
}
#[test]
fn timeout_page_wait_precedes_mask_and_retains_original_descriptor_and_timeout_origin() {
    let (linux, mut memory, fd, ring) = setup(4);
    let mask = mask();
    let source = caller(&linux, &memory, 7, Some(mask.clone()));
    let wake = target();
    memory.unmap(0x3000, PAGE_SIZE).unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x3000);
    descriptor(&mut memory, 0x2700, 8, 0x3000);
    memory.write_array(0x2700, 8u64.to_le_bytes()).unwrap();
    let args = [fd as u64, 0, 1, 9, 0x2600, 24];
    let IoAttempt::Blocked(wait) = source
        .start(426, args, &mut memory, 7, &Arc::downgrade(&wake), None)
        .unwrap()
    else {
        panic!("actual timeout page");
    };
    assert_eq!(mask.entered.load(Relaxed), 0);
    descriptor(&mut memory, 0x9000, 3, 0x9000);
    page.finish();
    memory.write_array(0x3000, 600u64.to_le_bytes()).unwrap();
    let IoAttempt::Blocked(wait) = source.resume(wait, &mut memory) else {
        panic!("original CQ wait");
    };
    assert_eq!(mask.value.load(Relaxed), 8);
    assert_eq!(mask.entered.load(Relaxed), 1);
    let deadline = wait.deadline;
    memory.write(0x3000, &[0; 16]).unwrap();
    memory.write_array(0x2700, 16u64.to_le_bytes()).unwrap();
    let IoAttempt::Blocked(wait) = source.resume(wait, &mut memory) else {
        panic!("accepted fields are not reimported");
    };
    assert_eq!(wait.deadline, deadline);
    assert!(ring.state.lock().unwrap().waits.contains_key(&7));
    wait.cancel_copies();
    assert_eq!(mask.value.load(Relaxed), 4);
}
#[test]
fn masked_wait_retains_ring_across_fd_reuse_and_old_receipt_cannot_finish_a_later_wait() {
    let (mut linux, mut memory, fd, ring) = setup(4);
    let alias = linux.vfs.dup(fd, 0, false).unwrap();
    let mask = mask();
    let source = caller(&linux, &memory, 7, Some(mask.clone()));
    let wake = target();
    descriptor(&mut memory, 0x2700, 8, 0);
    memory.write_array(0x2700, 8u64.to_le_bytes()).unwrap();
    let IoAttempt::Blocked(wait) = source
        .start(
            426,
            [fd as u64, 0, 1, 9, 0x2600, 24],
            &mut memory,
            7,
            &Arc::downgrade(&wake),
            None,
        )
        .unwrap()
    else {
        panic!("masked CQ wait");
    };
    let old = wait.uring_enter().unwrap();
    linux.vfs.close(fd).unwrap();
    assert_eq!(linux.vfs.eventfd(7, 0).unwrap(), fd);
    add(&mut memory, &ring, sqe(0, 0, 101));
    let other = caller(&linux, &memory, 8, None);
    assert_eq!(
        result(
            other
                .start(
                    426,
                    [alias as u64, 1, 0, 0, 0, 0],
                    &mut memory,
                    8,
                    &Arc::downgrade(&wake),
                    None
                )
                .unwrap()
        ),
        Ok(1)
    );
    assert_eq!(result(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(mask.value.load(Relaxed), 4);
    assert!(
        old.ring().is_none(),
        "completed snapshots release their original ring ownership"
    );
    assert_eq!(linux.vfs.read(fd, 8).unwrap(), 7u64.to_le_bytes());
    mask.value.store(128, Relaxed);
    memory.write_array(0x2700, 16u64.to_le_bytes()).unwrap();
    let IoAttempt::Blocked(next) = source
        .start(
            426,
            [alias as u64, 0, 2, 9, 0x2600, 24],
            &mut memory,
            7,
            &Arc::downgrade(&wake),
            None,
        )
        .unwrap()
    else {
        panic!("later masked wait");
    };
    assert_eq!(mask.value.load(Relaxed), 16);
    assert_eq!(
        result(source.start_retained_uring(
            old.clone(),
            [0; 6],
            &mut memory,
            7,
            &Arc::downgrade(&wake)
        )),
        Ok(0)
    );
    old.cancel();
    assert_eq!(mask.value.load(Relaxed), 16);
    assert!(ring.state.lock().unwrap().waits.contains_key(&7));
    next.cancel_copies();
    assert_eq!(mask.value.load(Relaxed), 128);
}
#[test]
fn signal_interruption_preserves_submitted_count_and_defers_the_original_mask() {
    for submitted in [0u64, 1] {
        let (linux, mut memory, fd, ring) = setup(4);
        let mask = mask();
        let source = caller(&linux, &memory, 7, Some(mask.clone()));
        let wake = target();
        descriptor(&mut memory, 0x2700, 8, 0);
        memory.write_array(0x2700, 8u64.to_le_bytes()).unwrap();
        if submitted != 0 {
            add(&mut memory, &ring, sqe(0, 0, 101));
        }
        let IoAttempt::Blocked(wait) = source
            .start(
                426,
                [fd as u64, submitted, 2, 9, 0x2600, 24],
                &mut memory,
                7,
                &Arc::downgrade(&wake),
                None,
            )
            .unwrap()
        else {
            panic!("wait after any accepted submission");
        };
        let receipt = wait.uring_enter().unwrap();
        assert_eq!(
            receipt.interrupted(),
            if submitted == 0 {
                Err(Errno(4))
            } else {
                Ok(submitted)
            }
        );
        assert_eq!(mask.value.load(Relaxed), 8);
        assert_eq!(mask.deferred.load(Relaxed), 1);
        assert_eq!(
            result(source.resume(wait, &mut memory)),
            if submitted == 0 {
                Err(Errno(4))
            } else {
                Ok(submitted)
            }
        );
        assert!(!ring.state.lock().unwrap().waits.contains_key(&7));
    }
}
#[test]
fn pending_signal_after_mask_import_keeps_native_cq_override_and_saved_mask() {
    let (linux, mut memory, fd, _ring) = setup(4);
    let mask = mask();
    let source = caller(&linux, &memory, 7, Some(mask.clone()));
    let wake = target();
    descriptor(&mut memory, 0x2700, 8, 0);
    memory.write_array(0x2700, 8u64.to_le_bytes()).unwrap();
    mask.pending.store(true, Relaxed);
    assert_eq!(
        result(
            source
                .start(
                    426,
                    [fd as u64, 0, 1, 9, 0x2600, 24],
                    &mut memory,
                    7,
                    &Arc::downgrade(&wake),
                    None
                )
                .unwrap()
        ),
        Err(Errno(4))
    );
    assert_eq!(mask.deferred.load(Relaxed), 1);
    assert_eq!(mask.value.load(Relaxed), 8);
}
fn timing(ring: &Arc<Uring>, deadline: Option<Instant>, minimum: Option<Instant>) -> EnterControl {
    EnterControl {
        task: 7,
        args: [0; 6],
        submitted: 0,
        state: Mutex::new(Control {
            ring: Some(ring.clone()),
            lease: None,
            reader: None,
            deadline,
            minimum,
            timeouts: 0,
            interrupted: false,
            result: None,
        }),
    }
}
#[test]
fn minimum_timer_switches_once_and_sq_timeout_completions_release_the_wait() {
    let (_, _, _, ring) = setup(4);
    let start = Instant::now();
    let min = start + Duration::from_secs(10);
    let end = start + Duration::from_secs(100);
    let control = timing(&ring, Some(end), Some(min));
    assert!(matches!(control.poll_at(0,2,0,min),Decision::Pending(Some(at)) if at == end));
    assert!(
        matches!(control.poll_at(1,2,0,min+Duration::from_secs(1)),Decision::Pending(Some(at)) if at == end)
    );
    assert!(matches!(
        control.poll_at(1, 2, 0, end),
        Decision::Ready(Ok(()))
    ));
    assert!(matches!(
        timing(&ring, None, Some(min)).poll_at(0, 2, 0, min),
        Decision::Ready(Err(Errno(62)))
    ));
    assert!(
        matches!(timing(&ring,Some(start),Some(min)).poll_at(0,2,0,start),Decision::Pending(Some(at)) if at == min)
    );
    assert!(matches!(
        timing(&ring, Some(end), Some(min)).poll_at(1, 2, 0, min),
        Decision::Ready(Ok(()))
    ));
    assert!(matches!(
        timing(&ring, Some(end), Some(min)).poll_at(2, 2, 0, start),
        Decision::Ready(Ok(()))
    ));
    assert!(matches!(
        timing(&ring, Some(end), Some(min)).poll_at(0, 2, 1, start),
        Decision::Ready(Ok(()))
    ));
}
#[test]
fn bare_dispatch_defers_with_original_registers_and_exports_the_original_page_wait() {
    let (mut linux, mut memory, fd, ring) = setup(4);
    let source = caller(&linux, &memory, 7, None);
    memory.unmap(0x3000, PAGE_SIZE).unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x3000);
    memory.write(0x2ff0, &[0; 16]).unwrap();
    add(&mut memory, &ring, sqe(0, 0, 101));
    let mut cpu = trames_execution::Aarch64State::default();
    cpu.registers[..6].copy_from_slice(&[fd as u64, 1, 0, 9, 0x2ff0, 24]);
    cpu.registers[8] = 426;
    let original = cpu.clone();
    let mut output = crate::CapturedOutput::default();
    assert_eq!(
        linux.dispatch_task_untraced(7, &mut cpu, &mut memory, &mut output),
        crate::SyscallOutcome::Deferred
    );
    assert_eq!(cpu, original);
    assert_eq!(ring.state.lock().unwrap().head, 1);
    let wait = linux
        .take_uring_wait(7)
        .expect("accepted page wait can be handed off without replay");
    linux.vfs.close(fd).unwrap();
    assert_eq!(linux.vfs.eventfd(7, 0).unwrap(), fd);
    page.finish();
    assert_eq!(result(source.resume(wait, &mut memory)), Ok(1));
    assert_eq!(cq(&mut memory, &ring), (101, 0));
}
#[test]
fn bare_resume_keeps_original_scalars_and_imported_fields_without_numeric_fd_lookup() {
    let (mut linux, mut memory, fd, ring) = setup(4);
    descriptor(&mut memory, 0, 0, 0x2800);
    memory.write_array(0x2800, 600u64.to_le_bytes()).unwrap();
    let args = [fd as u64, 0, 1, 9, 0x2600, 24];
    assert_eq!(
        linux.uring_enter(args, &mut memory, None, 7),
        Ok((0, false))
    );
    linux.vfs.close(fd).unwrap();
    assert_eq!(linux.vfs.eventfd(1, 0).unwrap(), fd);
    memory.write(0x2600, &[255; 24]).unwrap();
    assert_eq!(
        linux.uring_enter([u64::MAX; 6], &mut memory, Some(0), 7),
        Ok((0, false))
    );
    let wait = linux.take_uring_wait(7).unwrap();
    assert!(Arc::ptr_eq(
        &wait.uring_enter().unwrap().ring().unwrap(),
        &ring
    ));
    wait.cancel_copies();
}
#[test]
fn bare_missing_task_handoff_keeps_mask_bytes_and_original_context() {
    let (mut linux, mut memory, fd, ring) = setup(4);
    descriptor(&mut memory, 0x2700, 8, 0);
    memory.write_array(0x2700, 8u64.to_le_bytes()).unwrap();
    assert_eq!(
        linux.uring_enter([fd as u64, 0, 1, 9, 0x2600, 24], &mut memory, None, 7),
        Ok((0, false))
    );
    let checkpoint = linux
        .take_uring_checkpoint(7)
        .expect("the original mask needs task authority");
    let file::FileBoundary::UringEnter(call) = checkpoint.take() else {
        panic!("accepted enter handoff");
    };
    memory.write_array(0x2700, 16u64.to_le_bytes()).unwrap();
    descriptor(&mut memory, 0x9000, 3, 0);
    let mask = mask();
    let source = caller(&linux, &memory, 7, Some(mask.clone()));
    let wake = target();
    let IoAttempt::Blocked(wait) = call.resume(&source, &mut memory, 7, &Arc::downgrade(&wake))
    else {
        panic!("original CQ wait");
    };
    assert_eq!(mask.value.load(Relaxed), 8);
    assert!(Arc::ptr_eq(
        &wait.uring_enter().unwrap().ring().unwrap(),
        &ring
    ));
    wait.cancel_copies();
    assert_eq!(mask.value.load(Relaxed), 4);
}
#[test]
fn canceled_parameter_copy_invalidates_old_page_wait_without_submitting_later_sqes() {
    let (linux, mut memory, fd, ring) = setup(4);
    let source = caller(&linux, &memory, 7, None);
    let wake = target();
    memory.unmap(0x3000, PAGE_SIZE).unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x3000);
    memory.write(0x2ff0, &[0; 16]).unwrap();
    add(&mut memory, &ring, sqe(0, 0, 101));
    let IoAttempt::Blocked(wait) = source
        .start(
            426,
            [fd as u64, 1, 0, 9, 0x2ff0, 24],
            &mut memory,
            7,
            &Arc::downgrade(&wake),
            None,
        )
        .unwrap()
    else {
        panic!("parameter page follows accepted submission");
    };
    wait.cancel_copies();
    add(&mut memory, &ring, sqe(0, 0, 102));
    page.finish();
    assert_eq!(result(source.resume(wait, &mut memory)), Err(Errno(4)));
    assert_eq!(ring.state.lock().unwrap().head, 1);
    assert_eq!(cq(&mut memory, &ring), (101, 0));
}
#[test]
fn a_new_sq_timeout_completion_releases_a_larger_cq_wait() {
    let (linux, mut memory, fd, ring) = setup(4);
    let source = caller(&linux, &memory, 7, None);
    let wake = target();
    memory.write_array(0x2800, 3600u64.to_le_bytes()).unwrap();
    let mut timer = sqe(11, u32::MAX, 4);
    timer[16..24].copy_from_slice(&0x2800u64.to_le_bytes());
    timer[24..28].copy_from_slice(&1u32.to_le_bytes());
    add(&mut memory, &ring, timer);
    let IoAttempt::Blocked(wait) = source
        .start(
            426,
            [fd as u64, 1, 4, 1, 0, 0],
            &mut memory,
            7,
            &Arc::downgrade(&wake),
            None,
        )
        .unwrap()
    else {
        panic!("original timeout has not expired");
    };
    memory.write(0x2900, &[0; 16]).unwrap();
    let mut update = sqe(12, u32::MAX, 5);
    update[8..16].copy_from_slice(&0x2900u64.to_le_bytes());
    update[16..24].copy_from_slice(&4u64.to_le_bytes());
    update[28..32].copy_from_slice(&2u32.to_le_bytes());
    add(&mut memory, &ring, update);
    let other = caller(&linux, &memory, 8, None);
    assert_eq!(
        result(
            other
                .start(
                    426,
                    [fd as u64, 1, 0, 0, 0, 0],
                    &mut memory,
                    8,
                    &Arc::downgrade(&wake),
                    None
                )
                .unwrap()
        ),
        Ok(1)
    );
    assert_eq!(result(source.resume(wait, &mut memory)), Ok(1));
    assert_eq!(cq(&mut memory, &ring), (5, 0));
    assert_eq!(cq(&mut memory, &ring), (4, -62));
    assert_eq!(ring.state.lock().unwrap().timeout_completions, 1);
}
