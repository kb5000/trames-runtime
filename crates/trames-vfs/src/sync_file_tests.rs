// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};

fn setup() -> (Vfs, Memory, u32) {
    let mut vfs = Vfs::default();
    vfs.set_runtime_info(1, RuntimeInfo::default());
    let fd = vfs.open_at(AT_FDCWD, b"/dev/sw_sync", 2, 0).unwrap();
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
    (vfs, memory, fd)
}
fn call(vfs: &Vfs, memory: &mut Memory, fd: u32, cmd: u32) -> Result<u64> {
    vfs.sync_file(fd)?
        .unwrap()
        .ioctl(&vfs.descriptor_factory(), cmd, 0x1000, memory)
}
fn create(vfs: &Vfs, memory: &mut Memory, fd: u32, value: u32) -> u32 {
    let mut bytes = [0; 40];
    bytes[..4].copy_from_slice(&value.to_le_bytes());
    bytes[4..9].copy_from_slice(b"test\0");
    memory.write_array(0x1000, bytes).unwrap();
    call(vfs, memory, fd, CREATE).unwrap();
    u32::from_le_bytes(memory.read_array::<4>(0x1024).unwrap())
}
fn increment(vfs: &Vfs, memory: &mut Memory, fd: u32, value: u32) {
    memory.write_array(0x1000, value.to_le_bytes()).unwrap();
    call(vfs, memory, fd, INC).unwrap();
}
fn merge(vfs: &Vfs, memory: &mut Memory, a: u32, b: u32) -> u32 {
    let mut bytes = [0; 48];
    bytes[32..36].copy_from_slice(&b.to_le_bytes());
    memory.write_array(0x1000, bytes).unwrap();
    call(vfs, memory, a, MERGE).unwrap();
    u32::from_le_bytes(memory.read_array::<4>(0x1024).unwrap())
}
fn info(vfs: &Vfs, memory: &mut Memory, fd: u32, count: u32) -> (i32, u32) {
    let mut bytes = [0; 56];
    bytes[40..44].copy_from_slice(&count.to_le_bytes());
    bytes[48..56].copy_from_slice(&0x2000u64.to_le_bytes());
    memory.write_array(0x1000, bytes).unwrap();
    call(vfs, memory, fd, INFO).unwrap();
    let bytes = memory.read_array::<56>(0x1000).unwrap();
    (
        i32::from_le_bytes(bytes[32..36].try_into().unwrap()),
        u32::from_le_bytes(bytes[40..44].try_into().unwrap()),
    )
}
#[test]
fn merged_points_notify_original_epoll_and_finish_without_a_service() {
    let (mut vfs, mut memory, timeline) = setup();
    let other = vfs.open_at(AT_FDCWD, b"/dev/sw_sync", 2, 0).unwrap();
    let early = create(&vfs, &mut memory, timeline, 1);
    let late = create(&vfs, &mut memory, timeline, 3);
    let foreign = create(&vfs, &mut memory, other, 1);
    let same = merge(&vfs, &mut memory, early, late);
    assert_eq!(info(&vfs, &mut memory, same, 0), (0, 1));
    let merged = merge(&vfs, &mut memory, same, foreign);
    assert_eq!(info(&vfs, &mut memory, merged, 2), (0, 2));
    let epoll = vfs.epoll_create(0).unwrap();
    vfs.epoll_ctl(epoll, 1, merged, 0x80000001, 42).unwrap();
    let direct = vfs.direct_descriptors().get(merged).unwrap().clone();
    struct Target(std::sync::atomic::AtomicUsize);
    impl IoWake for Target {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let target = Arc::new(Target(std::sync::atomic::AtomicUsize::new(0)));
    let erased: Arc<dyn IoWake> = target.clone();
    let signal = IoSignal::new(99, Arc::downgrade(&erased));
    let _subscriptions = direct.subscribe(&signal);
    increment(&vfs, &mut memory, timeline, 3);
    assert!(signal.ready());
    signal.reset();
    assert_eq!(vfs.poll(merged, 1), 0);
    increment(&vfs, &mut memory, other, 1);
    assert!(signal.ready());
    assert_eq!(vfs.poll(merged, 1), 1);
    assert_eq!(
        vfs.epoll_wait(epoll, 8, |_, _| Ok(None)).unwrap(),
        vec![(1, 42)]
    );
    assert!(vfs
        .epoll_wait(epoll, 8, |_, _| Ok(None))
        .unwrap()
        .is_empty());
    assert_eq!(info(&vfs, &mut memory, merged, 2), (1, 2));
    assert!(u64::from_le_bytes(memory.read_array::<8>(0x2048).unwrap()) > 0);
    assert!(target.0.load(Ordering::Relaxed) >= 2);
    assert_ne!(vfs.flags(merged).unwrap() & O_CLOEXEC, 0);
    assert_eq!(direct.read(8), Err(Errno(22)));
}
#[test]
fn timeline_close_errors_pending_points_only_after_last_original_ofd() {
    let (mut vfs, mut memory, timeline) = setup();
    let alias = vfs.dup(timeline, 0, false).unwrap();
    let done = create(&vfs, &mut memory, timeline, 0);
    let waiting = create(&vfs, &mut memory, timeline, 1);
    let _snapshot = vfs.direct_descriptors();
    let _poll = vfs.direct_descriptors().get(timeline).unwrap().clone();
    vfs.close(timeline).unwrap();
    assert_eq!(info(&vfs, &mut memory, waiting, 1), (0, 1));
    vfs.close(alias).unwrap();
    // A real accepted poll retains its original OFD until that operation ends.
    assert_eq!(info(&vfs, &mut memory, waiting, 1), (0, 1));
    drop(_poll);
    assert_eq!(info(&vfs, &mut memory, waiting, 1), (-2, 1));
    assert_eq!(vfs.poll(waiting, 1), 1);
    assert_eq!(info(&vfs, &mut memory, done, 1), (1, 1));
    let replacement = vfs.open_at(AT_FDCWD, b"/dev/sw_sync", 2, 0).unwrap();
    increment(&vfs, &mut memory, replacement, 10);
    assert_eq!(info(&vfs, &mut memory, waiting, 0), (-2, 1));
}
#[test]
fn failed_copyout_releases_reserved_fd_and_info_checks_original_buffers() {
    let (vfs, mut memory, timeline) = setup();
    memory.write_array(0x1000, [0; 40]).unwrap();
    memory.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
    assert_eq!(call(&vfs, &mut memory, timeline, CREATE), Err(Errno(14)));
    let original = vfs.fd_snapshot().len();
    memory.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    let fence = create(&vfs, &mut memory, timeline, 1);
    assert_eq!(vfs.fd_snapshot().len(), original + 1);
    let mut bad = [0; 56];
    bad[36] = 1;
    memory.write_array(0x1000, bad).unwrap();
    assert_eq!(call(&vfs, &mut memory, fence, INFO), Err(Errno(22)));
    bad[36] = 0;
    bad[40] = 1;
    memory.write_array(0x1000, bad).unwrap();
    assert_eq!(call(&vfs, &mut memory, fence, INFO), Err(Errno(14)));
    assert_eq!(vfs.fd_snapshot().len(), original + 1);
}
#[test]
fn unsigned_timeline_advances_follow_signed_32_bit_sequence_order() {
    let (vfs, mut memory, timeline) = setup();
    increment(&vfs, &mut memory, timeline, 0x7fffffff);
    let fence = create(&vfs, &mut memory, timeline, 0xfffffff0);
    assert_eq!(vfs.poll(fence, 1), 0);
    increment(&vfs, &mut memory, timeline, 0x7ffffff0);
    assert_eq!(vfs.poll(fence, 1), 0);
    increment(&vfs, &mut memory, timeline, 1);
    assert_eq!(vfs.poll(fence, 1), 1);
    let wrapped = create(&vfs, &mut memory, timeline, 5);
    assert_eq!(vfs.poll(wrapped, 1), 0);
    increment(&vfs, &mut memory, timeline, 21);
    assert_eq!(vfs.poll(wrapped, 1), 1);
}
