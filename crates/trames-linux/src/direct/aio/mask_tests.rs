// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use trames_memory::{Memory, Permissions, PAGE_SIZE};

struct Wake;
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
struct Mask {
    current: AtomicU64,
    last: AtomicU64,
    pending: AtomicBool,
    enters: AtomicUsize,
    finishes: AtomicUsize,
    deferred: AtomicUsize,
}
struct Lease {
    task: Arc<Mask>,
    original: u64,
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
            self.task.current.store(self.original, Relaxed);
            self.task.finishes.fetch_add(1, Relaxed);
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
        self.enters.fetch_add(1, Relaxed);
        self.last.store(mask, Relaxed);
        let original = self.current.swap(mask, Relaxed);
        Some(Arc::new(Lease {
            task: self,
            original,
            active: AtomicBool::new(true),
        }))
    }
}
fn fixture() -> (Aio, DirectSyscalls, Memory, Arc<Mask>, Arc<dyn IoWake>, u64) {
    let vfs = trames_vfs::Vfs::default();
    let aio = Aio::default();
    let mask = Arc::new(Mask {
        current: 4.into(),
        last: 0.into(),
        pending: false.into(),
        enters: 0.into(),
        finishes: 0.into(),
        deferred: 0.into(),
    });
    let source = DirectSyscalls::new(vfs.direct_descriptors())
        .with_aio(aio.clone(), vfs.native_events())
        .with_task_signal(mask.clone());
    let mut memory = Memory::default();
    memory.map(0x1000, 0x7000, Permissions::RW).unwrap();
    aio.setup([4, 0x1000, 0, 0, 0, 0], &mut memory).unwrap();
    let id = memory.read_u64(0x1000).unwrap();
    memory.write_array(0x1200, 0x1280u64.to_le_bytes()).unwrap();
    memory.write_array(0x1208, 8u64.to_le_bytes()).unwrap();
    memory
        .write_array(0x1280, (8u64 | (1 << 8) | (1 << 18)).to_le_bytes())
        .unwrap();
    (aio, source, memory, mask, Arc::new(Wake), id)
}
fn value(attempt: IoAttempt) -> Result<u64, Errno> {
    let IoAttempt::Complete(result) = attempt else {
        panic!("original call must complete");
    };
    result
}
#[test]
fn pgetevents_applies_original_mask_before_context_page_wait_and_restores_on_lookup_error() {
    let (_, source, mut memory, mask, wake, _) = fixture();
    memory.unmap(0x6000, PAGE_SIZE).unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x6000);
    let IoAttempt::Blocked(wait) = source
        .start(
            292,
            [0x6000, 0, 0, 0, 0, 0x1200],
            &mut memory,
            1,
            &Arc::downgrade(&wake),
            None,
        )
        .unwrap()
    else {
        panic!("original context lookup page must wait");
    };
    assert_eq!(mask.current.load(Relaxed), 8);
    assert_eq!(wait.interruptible_file_wait(), Some(false));
    memory.write_array(0x1280, 16u64.to_le_bytes()).unwrap();
    page.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Err(Errno(22)));
    assert_eq!(mask.current.load(Relaxed), 4);
    assert_eq!(mask.enters.load(Relaxed), 1);
    assert_eq!(mask.finishes.load(Relaxed), 1);
}
#[test]
fn pgetevents_descriptor_prefix_survives_wait_before_mask_installation() {
    let (_, source, mut memory, mask, wake, id) = fixture();
    memory.unmap(0x3000, PAGE_SIZE).unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x3000);
    memory.write_array(0x2ff8, 0x1280u64.to_le_bytes()).unwrap();
    let IoAttempt::Blocked(wait) = source
        .start(
            292,
            [id, 0, 0, 0, 0, 0x2ff8],
            &mut memory,
            1,
            &Arc::downgrade(&wake),
            None,
        )
        .unwrap()
    else {
        panic!("sigset descriptor must finish before applying its mask");
    };
    assert_eq!(mask.current.load(Relaxed), 4);
    memory.write_array(0x2ff8, 0u64.to_le_bytes()).unwrap();
    page.finish();
    memory.write_array(0x3000, 8u64.to_le_bytes()).unwrap();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(mask.last.load(Relaxed), 8);
    assert_eq!(mask.enters.load(Relaxed), 1);
    assert_eq!(mask.current.load(Relaxed), 4);
}
#[test]
fn pgetevents_null_mask_ignores_sigsetsize_and_bad_nonnull_size_precedes_mask_access() {
    for (pointer, size, error) in [
        (0u64, 7u64, None),
        (0x9000, 7, Some(22)),
        (0x9000, 8, Some(14)),
    ] {
        let (_, source, mut memory, mask, wake, id) = fixture();
        memory.write_array(0x1200, pointer.to_le_bytes()).unwrap();
        memory.write_array(0x1208, size.to_le_bytes()).unwrap();
        let result = value(
            source
                .start(
                    292,
                    [id, 0, 0, 0, 0, 0x1200],
                    &mut memory,
                    1,
                    &Arc::downgrade(&wake),
                    None,
                )
                .unwrap(),
        );
        assert_eq!(result, error.map_or(Ok(0), |error| Err(Errno(error))));
        assert_eq!(mask.enters.load(Relaxed), 0);
        assert_eq!(mask.current.load(Relaxed), 4);
    }
}
#[test]
fn pgetevents_missing_task_capability_hands_off_accepted_mask_without_rereading_parameters() {
    let (aio, source, mut memory, mask, wake, id) = fixture();
    let bare = DirectSyscalls::new(source.descriptors.clone())
        .with_aio(aio, source.aio.as_ref().unwrap().1.clone());
    let IoAttempt::FileCheckpoint(checkpoint) = bare
        .start(
            292,
            [id, 0, 0, 0, 0, 0x1200],
            &mut memory,
            1,
            &Arc::downgrade(&wake),
            None,
        )
        .unwrap()
    else {
        panic!("missing task authority must preserve the accepted input");
    };
    let file::FileBoundary::AioLookup(call) = checkpoint.take() else {
        panic!("original lookup capability");
    };
    memory.write_array(0x1280, 16u64.to_le_bytes()).unwrap();
    memory.write_array(0x1200, 0x9000u64.to_le_bytes()).unwrap();
    assert_eq!(
        value(call.resume(&source, &mut memory, 1, &Arc::downgrade(&wake))),
        Ok(0)
    );
    assert_eq!(mask.last.load(Relaxed), 8);
    assert_eq!(mask.current.load(Relaxed), 4);
}
#[test]
fn pgetevents_signal_pending_defers_mask_restore_for_zero_and_positive_event_results() {
    for available in [false, true] {
        let (aio, source, mut memory, mask, wake, id) = fixture();
        if available {
            let context = aio.context(id, &memory).unwrap();
            let mut state = context.state.lock().unwrap();
            context.publish(&mut state, [0x71; 32]);
        }
        mask.pending.store(true, Relaxed);
        let result = value(
            source
                .start(
                    292,
                    [id, 0, 1, 0x1600, 0, 0x1200],
                    &mut memory,
                    1,
                    &Arc::downgrade(&wake),
                    None,
                )
                .unwrap(),
        );
        assert_eq!(result, if available { Ok(1) } else { Err(Errno(4)) });
        assert_eq!(mask.current.load(Relaxed), 8);
        assert_eq!(mask.deferred.load(Relaxed), 1);
        assert_eq!(mask.finishes.load(Relaxed), 0);
    }
}
#[test]
fn pgetevents_output_wait_keeps_mask_until_completion_and_old_snapshot_cannot_restore_it_twice() {
    let (aio, source, mut memory, mask, wake, id) = fixture();
    let context = aio.context(id, &memory).unwrap();
    {
        let mut state = context.state.lock().unwrap();
        context.publish(&mut state, [0x71; 32]);
    }
    memory.unmap(0x3000, PAGE_SIZE).unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x3000);
    let IoAttempt::Blocked(wait) = source
        .start(
            292,
            [id, 1, 1, 0x2ff0, 0, 0x1200],
            &mut memory,
            1,
            &Arc::downgrade(&wake),
            None,
        )
        .unwrap()
    else {
        panic!("original event output crosses an actual backing wait");
    };
    let old = wait.aio.clone().unwrap();
    assert_eq!(mask.current.load(Relaxed), 8);
    page.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(1));
    assert_eq!(mask.current.load(Relaxed), 4);
    assert_eq!(mask.finishes.load(Relaxed), 1);
    mask.current.store(128, Relaxed);
    assert_eq!(
        value(source.start_retained_aio(old, &mut memory, 1, &Arc::downgrade(&wake))),
        Err(Errno(4))
    );
    assert_eq!(mask.current.load(Relaxed), 128);
    assert_eq!(mask.finishes.load(Relaxed), 1);
}
#[test]
fn aio_raw_signed_timeout_fields_are_converted_after_copy_and_do_not_preempt_sigmask_import() {
    for (seconds, nanos) in [(-1i64, 0i64), (0, 1_000_000_000), (i64::MAX, 0)] {
        let (_, source, mut memory, mask, wake, id) = fixture();
        memory.write_array(0x1400, seconds.to_le_bytes()).unwrap();
        memory.write_array(0x1408, nanos.to_le_bytes()).unwrap();
        assert_eq!(
            value(
                source
                    .start(
                        292,
                        [id, 0, 0, 0, 0x1400, 0x1200],
                        &mut memory,
                        1,
                        &Arc::downgrade(&wake),
                        None
                    )
                    .unwrap()
            ),
            Ok(0)
        );
        assert_eq!(mask.enters.load(Relaxed), 1);
        assert_eq!(mask.current.load(Relaxed), 4);
    }
}
