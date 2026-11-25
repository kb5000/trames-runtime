// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};
#[derive(Default)]
struct Disk(Mutex<Vec<(trames_vfs::FileWork, Arc<FileResult>)>>);
impl FileExecutor for Disk {
    fn submit_file(&self, work: trames_vfs::FileWork, result: Arc<FileResult>) {
        result.begin();
        self.0.lock().unwrap().push((work, result));
    }
}
impl Disk {
    fn complete(&self) {
        let requests = std::mem::take(&mut *self.0.lock().unwrap());
        for (work, result) in requests {
            result.complete(work.run());
        }
    }
}
struct Wake;
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn value(attempt: IoAttempt) -> Result<u64, Errno> {
    let IoAttempt::Complete(result) = attempt else {
        panic!("original AIO must complete");
    };
    result
}
fn event_result(context: &Context) -> i64 {
    let (page, offset) = context.event(0);
    let mut event = [0; 32];
    page.copy_read(offset, &mut event);
    assert_eq!(u64::from_le_bytes(event[..8].try_into().unwrap()), 123);
    assert_eq!(u64::from_le_bytes(event[8..16].try_into().unwrap()), 0x2000);
    i64::from_le_bytes(event[16..24].try_into().unwrap())
}
type Fixture = (
    trames_vfs::Vfs,
    DirectSyscalls,
    Memory,
    Arc<Disk>,
    PendingIo,
    Arc<Context>,
    u64,
    u32,
    u32,
    Arc<dyn IoWake>,
);
fn fixture(write: bool, address: u64) -> Fixture {
    let mut vfs = trames_vfs::Vfs::default();
    vfs.import_file(b"/data", b"abcdefgh".to_vec()).unwrap();
    let fd = vfs.open_at(-100, b"/data", 2, 0).unwrap();
    let event = vfs.eventfd(0, 0x800).unwrap();
    let aio = Aio::default();
    let disk = Arc::new(Disk::default());
    let source = DirectSyscalls::new(vfs.direct_descriptors())
        .with_aio(aio.clone(), vfs.native_events())
        .with_paths(vfs.path_queries())
        .with_file_executor(disk.clone());
    let mut memory = Memory::default();
    memory.map(0x1000, 0x5000, Permissions::RW).unwrap();
    memory.write(address, b"written!").unwrap();
    aio.setup([8, 0x1000, 0, 0, 0, 0], &mut memory).unwrap();
    let id = memory.read_u64(0x1000).unwrap();
    let context = aio.context(id, &memory).unwrap();
    let mut cb = [0; 64];
    cb[..8].copy_from_slice(&123u64.to_le_bytes());
    cb[16..18].copy_from_slice(&u16::from(write).to_le_bytes());
    cb[20..24].copy_from_slice(&fd.to_le_bytes());
    cb[24..32].copy_from_slice(&address.to_le_bytes());
    cb[32..40].copy_from_slice(&8u64.to_le_bytes());
    cb[56..60].copy_from_slice(&1u32.to_le_bytes());
    cb[60..64].copy_from_slice(&event.to_le_bytes());
    memory.write_array(0x2000, cb).unwrap();
    memory.write_array(0x1800, 0x2000u64.to_le_bytes()).unwrap();
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let Some(IoAttempt::Blocked(wait)) = source.start(
        2,
        [id, 1, 0x1800, 0, 0, 0],
        &mut memory,
        1,
        &Arc::downgrade(&wake),
        None,
    ) else {
        panic!("original native request");
    };
    (
        vfs, source, memory, disk, wait, context, id, fd, event, wake,
    )
}
#[test]
fn fatal_submit_waits_for_actual_write_and_publishes_original_event_before_destroy() {
    let (mut vfs, source, mut memory, disk, wait, context, id, fd, event, wake) =
        fixture(true, 0x3000);
    let duplicate = vfs.dup(event, 0, false).unwrap();
    let call = wait.aio.clone().unwrap();
    let IoAttempt::Blocked(exiting) =
        source.drain_aio_exit(call, &mut memory, 1, &Arc::downgrade(&wake))
    else {
        panic!("exit waits for native write");
    };
    assert!(exiting.aio.as_ref().unwrap().exit_waiting());
    assert!(!exiting.signal.ready());
    assert_eq!(context.state.lock().unwrap().tail, 0);
    assert_eq!(vfs.read(duplicate, 8), Err(Errno(11)));
    vfs.shared_files().close_range(event, event, 0, 1).unwrap();
    assert_eq!(vfs.eventfd(0, 0x800).unwrap(), event);
    let Some(IoAttempt::Blocked(destroy)) = source.start(
        1,
        [id, 0, 0, 0, 0, 0],
        &mut memory,
        2,
        &Arc::downgrade(&wake),
        None,
    ) else {
        panic!("destroy waits for original submit");
    };
    disk.complete();
    assert_eq!(
        value(source.drain_aio_exit(exiting.aio.unwrap(), &mut memory, 1, &Arc::downgrade(&wake))),
        Ok(1)
    );
    assert_eq!(event_result(&context), 8);
    assert_eq!(vfs.pread(fd, 8, 0).unwrap(), b"written!");
    assert_eq!(vfs.read(duplicate, 8).unwrap(), 1u64.to_le_bytes());
    assert_eq!(vfs.read(event, 8), Err(Errno(11)));
    assert_eq!(
        value(source.drain_aio_exit(destroy.aio.unwrap(), &mut memory, 2, &Arc::downgrade(&wake))),
        Ok(0)
    );
    assert_eq!(context.state.lock().unwrap().destroyers, 0);
}
#[test]
fn fatal_read_copy_publishes_actual_prefix_or_fault_without_replaying_earlier_stores() {
    for prefix in [0, 2] {
        let address = 0x4000 - prefix;
        let (mut vfs, source, mut memory, disk, wait, context, _id, _fd, event, wake) =
            fixture(false, address);
        memory.unmap(0x4000, PAGE_SIZE).unwrap();
        let _page = file::copyout_tests::install(&mut memory, 0x4000);
        disk.complete();
        let IoAttempt::Blocked(wait) = source.resume(wait, &mut memory) else {
            panic!("original output waits");
        };
        if prefix != 0 {
            memory.write(address, b"zz").unwrap();
        }
        assert_eq!(
            value(source.drain_aio_exit(wait.aio.unwrap(), &mut memory, 1, &Arc::downgrade(&wake))),
            Ok(1)
        );
        assert_eq!(event_result(&context), if prefix == 0 { -14 } else { 2 });
        if prefix != 0 {
            assert_eq!(memory.read_array::<2>(address).unwrap(), *b"zz");
        }
        assert_eq!(vfs.read(event, 8).unwrap(), 1u64.to_le_bytes());
    }
}
#[test]
fn last_mm_close_waits_for_destroy_mapping_writeback_and_releases_its_original_context() {
    struct Completion(Arc<Mutex<usize>>);
    impl trames_memory::SyncCompletion for Completion {
        fn complete(self: Box<Self>, result: Result<(), trames_memory::MemoryError>) {
            assert_eq!(result, Ok(()));
            *self.0.lock().unwrap() += 1;
        }
    }
    let (_vfs, source, mut memory, disk, wait, context, id, _fd, _event, wake) =
        fixture(true, 0x3000);
    let Some(IoAttempt::Blocked(mut destroy)) = source.start(
        1,
        [id, 0, 0, 0, 0, 0],
        &mut memory,
        2,
        &Arc::downgrade(&wake),
        None,
    ) else {
        panic!("original destroy waits");
    };
    let mapping_close = Arc::new(FileResult::default());
    destroy.retain_aio_mapping_close(mapping_close.clone());
    disk.complete();
    assert_eq!(
        value(source.drain_aio_exit(wait.aio.unwrap(), &mut memory, 1, &Arc::downgrade(&wake))),
        Ok(1)
    );
    let completed = Arc::new(Mutex::new(0));
    assert!(memory.close_resources()[0]
        .sync_async(Box::new(Completion(completed.clone())))
        .is_ok());
    let IoAttempt::Blocked(destroy) =
        source.drain_aio_exit(destroy.aio.unwrap(), &mut memory, 2, &Arc::downgrade(&wake))
    else {
        panic!("destroy retains original writeback");
    };
    let original = Arc::downgrade(&context);
    destroy.cancel_copies();
    drop(destroy);
    drop(context);
    assert_eq!(*completed.lock().unwrap(), 0);
    assert!(original.upgrade().is_some());
    mapping_close.fail(5);
    assert_eq!(*completed.lock().unwrap(), 1);
    assert!(original.upgrade().is_none());
}
