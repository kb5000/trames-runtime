// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use trames_memory::{Memory, Permissions, PAGE_SIZE};

struct Target;
impl IoWake for Target {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn target() -> Arc<dyn IoWake> {
    Arc::new(Target)
}
fn page_wait(attempt: IoAttempt) -> PendingIo {
    let IoAttempt::Blocked(wait) = attempt else {
        panic!("reached input/output page must retain the original call");
    };
    assert_eq!(wait.interruptible_file_wait(), Some(false));
    assert_eq!(wait.wake_deadline(), None);
    wait
}
struct Mask {
    current: AtomicU64,
    enters: AtomicUsize,
    finishes: AtomicUsize,
}
struct Lease {
    owner: Arc<Mask>,
    original: u64,
    active: AtomicBool,
}
impl trames_vfs::TemporaryMask for Lease {
    fn signal_pending(&self) -> bool {
        false
    }
    fn finish(&self) {
        if self.active.swap(false, Ordering::Relaxed) {
            self.owner.current.store(self.original, Ordering::Relaxed);
            self.owner.finishes.fetch_add(1, Ordering::Relaxed);
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
        self.enters.fetch_add(1, Ordering::Relaxed);
        let original = self.current.swap(mask, Ordering::Relaxed);
        Some(Arc::new(Lease {
            owner: self,
            original,
            active: AtomicBool::new(true),
        }))
    }
}

#[test]
fn poll_array_fragments_survive_input_fault_and_fd_lookup_occurs_after_the_complete_copy() {
    let mut v = trames_vfs::Vfs::default();
    let fd = v.eventfd(1, 0).unwrap();
    let other = v.eventfd(2, 0).unwrap();
    let source = DirectSyscalls::new(v.direct_descriptors());
    let target = target();
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    memory
        .write_array(0x10ff8, (fd as u64 | (1u64 << 32)).to_le_bytes())
        .unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x11000);
    let args = [0x10ff8, 2, 0, 0, 0, 0];
    let wait = page_wait(
        source
            .start(73, args, &mut memory, 1, &Arc::downgrade(&target), None)
            .unwrap(),
    );
    memory
        .write_array(0x10ff8, (other as u64 | (1u64 << 32)).to_le_bytes())
        .unwrap();
    v.shared_files().close_range(fd, fd, 0, 1).unwrap();
    assert_eq!(v.eventfd(0, 0).unwrap(), fd);
    v.set_descriptor_limit(0);
    page.finish();
    memory.write_array(0x11000, u32::MAX.to_le_bytes()).unwrap();
    let IoAttempt::Blocked(wait) = source.resume(wait, &mut memory) else {
        panic!("cached original row reaches the replacement only after all input is copied");
    };
    assert!(wait.retained_poll.is_some());
    assert_eq!(
        wait.interruptible_file_wait(),
        None,
        "input completed; this is ordinary readiness waiting"
    );
    v.write(fd, &1u64.to_le_bytes()).unwrap();
    assert!(matches!(
        source.resume(wait, &mut memory),
        IoAttempt::Complete(Ok(1))
    ));
    assert_eq!(memory.read_array::<2>(0x10ffe).unwrap(), 1u16.to_le_bytes());
    assert_eq!(
        memory.read_array::<4>(0x10ff8).unwrap(),
        other.to_le_bytes(),
        "output does not rewrite the accepted input row"
    );
}

#[test]
fn pselect_copies_argument_pack_before_timeout_and_preserves_its_successful_word() {
    let source = DirectSyscalls::default();
    let target = target();
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    memory
        .write_array(0x10ff8, 0x10020u64.to_le_bytes())
        .unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x11000);
    let args = [0, 0, 0, 0, 0x9000, 0x10ff8];
    let wait = page_wait(
        source
            .start(72, args, &mut memory, 1, &Arc::downgrade(&target), None)
            .unwrap(),
    );
    memory.write_array(0x10ff8, 0u64.to_le_bytes()).unwrap();
    page.finish();
    memory.write_array(0x11000, 8u64.to_le_bytes()).unwrap();
    assert!(
        matches!(
            source.resume(wait, &mut memory),
            IoAttempt::Complete(Err(Errno(14)))
        ),
        "timeout fault follows the original imported argument pack"
    );
}

#[test]
fn mask_and_timeout_origin_survive_input_wait_and_restore_before_faultable_timeout_output() {
    let source_mask = Arc::new(Mask {
        current: AtomicU64::new(4),
        enters: AtomicUsize::new(0),
        finishes: AtomicUsize::new(0),
    });
    let v = trames_vfs::Vfs::default();
    let source = DirectSyscalls::new(v.direct_descriptors()).with_task_signal(source_mask.clone());
    let target = target();
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.map(0x12000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.write_array(0x10020, 1u64.to_le_bytes()).unwrap();
    let input = file::copyout_tests::install(&mut memory, 0x11000);
    let args = [0x11000, 1, 0x12000, 0x10020, 8, 0];
    let deadline = Instant::now();
    let wait = page_wait(
        source
            .start(
                73,
                args,
                &mut memory,
                1,
                &Arc::downgrade(&target),
                Some(deadline),
            )
            .unwrap(),
    );
    assert_eq!(
        source_mask.current.load(Ordering::Relaxed),
        1,
        "mask applies before array fault"
    );
    memory.write_array(0x10020, 2u64.to_le_bytes()).unwrap();
    memory.unmap(0x12000, PAGE_SIZE).unwrap();
    let output = file::copyout_tests::install(&mut memory, 0x12000);
    input.finish();
    memory.write_array(0x11000, u32::MAX.to_le_bytes()).unwrap();
    let wait = page_wait(source.resume(wait, &mut memory));
    assert_eq!(
        wait.retained_poll.as_ref().unwrap().deadline,
        Some(deadline)
    );
    assert_eq!(
        source_mask.current.load(Ordering::Relaxed),
        4,
        "normal result restores mask before timeout copy"
    );
    assert_eq!(source_mask.enters.load(Ordering::Relaxed), 1);
    output.finish();
    assert!(matches!(
        source.resume(wait, &mut memory),
        IoAttempt::Complete(Ok(0))
    ));
    assert_eq!(source_mask.finishes.load(Ordering::Relaxed), 1);
}

#[test]
fn zero_timeout_never_requires_write_permission_for_the_timespec() {
    let source = DirectSyscalls::default();
    let target = target();
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::R).unwrap();
    assert!(matches!(
        source
            .start(
                73,
                [u64::MAX, 0, 0x10000, 0, 0, 0],
                &mut memory,
                1,
                &Arc::downgrade(&target),
                None
            )
            .unwrap(),
        IoAttempt::Complete(Ok(0))
    ));
}

#[test]
fn select_keeps_the_original_fdtable_extent_while_a_later_input_set_faults() {
    let mut v = trames_vfs::Vfs::default();
    let source = DirectSyscalls::new(v.direct_descriptors());
    let target = target();
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    memory
        .write_array(0x10008, (1u64 << 36).to_le_bytes())
        .unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x11000);
    let args = [128, 0x10000, 0x11000, 0, 0x10040, 0];
    let wait = page_wait(
        source
            .start(72, args, &mut memory, 1, &Arc::downgrade(&target), None)
            .unwrap(),
    );
    for _ in 0..70 {
        v.dup(0, 0, false).unwrap();
    }
    page.finish();
    assert!(matches!(
        source.resume(wait, &mut memory),
        IoAttempt::Complete(Ok(0))
    ));
    assert_eq!(
        memory.read_array::<8>(0x10008).unwrap(),
        (1u64 << 36).to_le_bytes(),
        "fdtable growth cannot import or overwrite a set tail outside the original extent"
    );
}
