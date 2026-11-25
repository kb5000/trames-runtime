// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};
use trames_vfs::{binder::abi, Vfs};
struct Target;
impl IoWake for Target {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn owner() -> (Vfs, u32) {
    let mut vfs = Vfs::default();
    vfs.set_lock_owner(10);
    vfs.set_runtime_info(10, trames_vfs::RuntimeInfo::default());
    let fd = vfs.open_at(-100, b"/dev/binder", 2, 0).unwrap();
    (vfs, fd)
}
fn blocked(attempt: IoAttempt) -> PendingIo {
    let IoAttempt::Blocked(wait) = attempt else {
        panic!("expected original Binder wait");
    };
    assert!(wait.binder.is_some());
    assert_eq!(wait.wake_deadline(), None);
    wait
}
#[test]
fn control_copy_survives_fd_reuse_and_executor_handoff_on_the_original_page_wait() {
    let (mut vfs, fd) = owner();
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x11000);
    let target: Arc<dyn IoWake> = Arc::new(Target);
    let direct = DirectSyscalls::default().with_resources(vfs.descriptor_factory());
    let args = [fd as u64, abi::VERSION as u64, 0x10ffe, 0, 0, 0];
    let wait = blocked(
        direct
            .start(29, args, &mut memory, 10, &Arc::downgrade(&target), None)
            .unwrap(),
    );
    assert_eq!(wait.interruptible_file_wait(), Some(false));
    assert!(wait.notification_external());
    assert!(!wait.signal.ready());
    let original = wait.binder.clone().unwrap();
    vfs.close(fd).unwrap();
    assert_eq!(vfs.eventfd(99, 0).unwrap(), fd);
    memory.write(0x10ffe, b"XY").unwrap();
    page.finish();
    assert!(wait.signal.ready());
    drop(wait);
    assert!(matches!(
        DirectSyscalls::default().start_retained_binder(
            original,
            &mut memory,
            10,
            &Arc::downgrade(&target)
        ),
        IoAttempt::Complete(Ok(0))
    ));
    assert_eq!(memory.read_array::<4>(0x10ffe).unwrap(), [b'X', b'Y', 0, 0]);
    assert_eq!(vfs.read(fd, 8).unwrap(), 99u64.to_le_bytes());
}
#[test]
fn interrupt_keeps_the_accepted_header_and_copy_cursor_across_the_last_page() {
    let (vfs, fd) = owner();
    let target: Arc<dyn IoWake> = Arc::new(Target);
    let direct = DirectSyscalls::default().with_resources(vfs.descriptor_factory());
    let mut memory = Memory::default();
    memory.map(0x10000, 3 * PAGE_SIZE, Permissions::RW).unwrap();
    let mut header = [0; 48];
    header[24..32].copy_from_slice(&4096u64.to_le_bytes());
    header[40..48].copy_from_slice(&0x12000u64.to_le_bytes());
    memory.write(0x10ff0, &header).unwrap();
    let args = [fd as u64, abi::WRITE_READ as u64, 0x10ff0, 0, 0, 0];
    let wait = blocked(
        direct
            .start(29, args, &mut memory, 10, &Arc::downgrade(&target), None)
            .unwrap(),
    );
    assert_eq!(wait.interruptible_file_wait(), Some(true));
    let original = wait.binder.clone().unwrap();
    drop(wait);
    memory.unmap(0x11000, PAGE_SIZE).unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x11000);
    assert_eq!(original.interrupted(&mut memory), None);
    assert!(original.copy_fault().is_some());
    assert!(!original.interruptible());
    memory.write(0x10ff0, b"KEEP").unwrap();
    page.finish();
    assert_eq!(original.interrupted(&mut memory), Some(Err(Errno(4))));
    assert_eq!(memory.read_array::<4>(0x10ff0).unwrap(), *b"KEEP");
    assert_eq!(
        memory.read_u64(0x11010).unwrap(),
        0,
        "EINTR retains original read_consumed despite copied NOOP"
    );
    assert_eq!(memory.read_u64(0x11018).unwrap(), 0x12000);
}
#[test]
fn cancelling_a_shared_copy_invalidates_old_handoff_clones() {
    let (vfs, fd) = owner();
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x11000);
    let target: Arc<dyn IoWake> = Arc::new(Target);
    let direct = DirectSyscalls::default().with_resources(vfs.descriptor_factory());
    let wait = blocked(
        direct
            .start(
                29,
                [fd as u64, abi::VERSION as u64, 0x10ffe, 0, 0, 0],
                &mut memory,
                10,
                &Arc::downgrade(&target),
                None,
            )
            .unwrap(),
    );
    let original = wait.binder.clone().unwrap();
    original.cancel();
    drop(wait);
    memory.write(0x10ffe, b"XY").unwrap();
    page.finish();
    memory.write(0x11000, b"ZZ").unwrap();
    assert!(matches!(
        DirectSyscalls::default().start_retained_binder(
            original,
            &mut memory,
            10,
            &Arc::downgrade(&target)
        ),
        IoAttempt::Complete(Err(Errno(4)))
    ));
    assert_eq!(
        memory.read_array::<4>(0x10ffe).unwrap(),
        [b'X', b'Y', b'Z', b'Z']
    );
}
