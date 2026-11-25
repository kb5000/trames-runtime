// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions};
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
#[derive(Default)]
struct Completed(Mutex<Vec<Result<(), MemoryError>>>);
struct Completion(Arc<Completed>);
impl SyncCompletion for Completion {
    fn complete(self: Box<Self>, result: Result<(), MemoryError>) {
        self.0 .0.lock().unwrap().push(result);
    }
}
type Fixture = (
    Aio,
    DirectSyscalls,
    Memory,
    Arc<Disk>,
    PendingIo,
    Arc<Context>,
    u64,
    Arc<dyn IoWake>,
);
fn fixture(pipe: bool) -> Fixture {
    let mut vfs = trames_vfs::Vfs::default();
    let fd = if pipe {
        vfs.pipe(0).unwrap()[0]
    } else {
        vfs.import_file(b"/original", b"data".to_vec()).unwrap();
        vfs.open_at(-100, b"/original", 0, 0).unwrap()
    };
    let aio = Aio::default();
    let disk = Arc::new(Disk::default());
    let source = DirectSyscalls::new(vfs.direct_descriptors())
        .with_aio(aio.clone(), vfs.native_events())
        .with_paths(vfs.path_queries())
        .with_file_executor(disk.clone());
    let mut memory = Memory::default();
    memory.map(0x1000, 0x5000, Permissions::RW).unwrap();
    aio.setup([8, 0x1000, 0, 0, 0, 0], &mut memory).unwrap();
    let id = memory.read_u64(0x1000).unwrap();
    let context = aio.context(id, &memory).unwrap();
    let mut cb = [0; 64];
    cb[20..24].copy_from_slice(&fd.to_le_bytes());
    cb[24..32].copy_from_slice(&0x3000u64.to_le_bytes());
    cb[32..40].copy_from_slice(&4u64.to_le_bytes());
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
        panic!("accepted original request");
    };
    (aio, source, memory, disk, wait, context, id, wake)
}
#[test]
fn ordinary_unmap_and_fork_do_not_run_or_inherit_last_mm_aio_teardown() {
    let (_aio, _source, mut memory, _disk, wait, context, id, _wake) = fixture(true);
    let child = memory.clone();
    assert!(child.close_resources().is_empty());
    memory.unmap(id, context.mapping.length).unwrap();
    assert!(memory.take_closed_resources().is_empty());
    assert!(!context.state.lock().unwrap().dead);
    assert_eq!(
        memory.close_resources().len(),
        1,
        "unmapping the ring cannot lose mm-owned context teardown"
    );
    wait.cancel_copies();
}
#[test]
fn last_mm_waits_for_native_requests_even_after_io_destroy_detaches_original_context() {
    let (_aio, source, mut memory, disk, wait, context, id, wake) = fixture(false);
    let Some(IoAttempt::Blocked(destroy)) = source.start(
        1,
        [id, 0, 0, 0, 0, 0],
        &mut memory,
        2,
        &Arc::downgrade(&wake),
        None,
    ) else {
        panic!("destroy waits for original native work");
    };
    wait.cancel_copies();
    destroy.cancel_copies();
    let resources = memory.close_resources();
    assert_eq!(resources.len(), 1);
    let first = Arc::new(Completed::default());
    let second = Arc::new(Completed::default());
    assert!(resources[0]
        .sync_async(Box::new(Completion(first.clone())))
        .is_ok());
    assert!(resources[0]
        .sync_async(Box::new(Completion(second.clone())))
        .is_ok());
    assert!(first.0.lock().unwrap().is_empty());
    assert!(second.0.lock().unwrap().is_empty());
    assert!(context.state.lock().unwrap().active.contains(&0x2000));
    disk.complete();
    assert_eq!(*first.0.lock().unwrap(), vec![Ok(())]);
    assert_eq!(*second.0.lock().unwrap(), vec![Ok(())]);
    assert!(context.state.lock().unwrap().active.is_empty());
    assert_eq!(memory.read_array::<4>(0x3000).unwrap(), [0; 4]);
}
#[test]
fn final_context_teardown_wakes_original_pipe_caller_and_finishes_on_its_existing_slot() {
    let (aio, source, mut memory, _disk, wait, context, _id, wake) = fixture(true);
    let resource = memory.close_resources().pop().unwrap();
    let completed = Arc::new(Completed::default());
    assert!(resource
        .sync_async(Box::new(Completion(completed.clone())))
        .is_ok());
    assert!(context.state.lock().unwrap().dead);
    assert!(wait.signal.ready());
    assert!(completed.0.lock().unwrap().is_empty());
    assert!(matches!(
        source.drain_aio_exit(wait.aio.unwrap(), &mut memory, 1, &Arc::downgrade(&wake)),
        IoAttempt::Complete(Ok(1))
    ));
    assert_eq!(*completed.0.lock().unwrap(), vec![Ok(())]);
    assert_eq!(
        aio.setup([8, 0x1100, 0, 0, 0, 0], &mut memory),
        Err(Errno(22))
    );
}

#[test]
fn losing_the_close_executor_releases_its_receipt_but_keeps_accepted_native_aio_alive() {
    #[derive(Default)]
    struct HostQueue(Mutex<Vec<Box<dyn crate::HostFileTask>>>);
    impl FileExecutor for HostQueue {
        fn submit_file(&self, _: trames_vfs::FileWork, _: Arc<FileResult>) {
            panic!("no AIO replay")
        }
        fn submit_host(
            &self,
            work: Box<dyn crate::HostFileTask>,
            admission: Option<crate::HostFileAdmission>,
        ) {
            assert!(admission.is_none(), "AIO last-mm close has no file layout");
            self.0.lock().unwrap().push(work);
        }
    }
    let (_aio, _source, memory, disk, wait, context, _id, _wake) = fixture(false);
    wait.cancel_copies();
    let resource = memory.close_resources().pop().unwrap();
    let queue = Arc::new(HostQueue::default());
    let layouts = crate::FileLayouts::new(queue.clone());
    let notified = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = notified.clone();
    let result = layouts.close_mappings_notify(
        vec![resource],
        77,
        Some(Box::new(move || {
            observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        })),
    );
    let job = queue.0.lock().unwrap().pop().unwrap();
    job.run(None);
    assert!(!result.ready());
    assert!(context.state.lock().unwrap().active.contains(&0x2000));
    assert_eq!(disk.0.lock().unwrap().len(), 1);
    drop(layouts);
    let Some(trames_vfs::FileOutcome::Complete(reply)) = result.take() else {
        panic!("retired close receipt")
    };
    assert!(matches!(reply.result, Ok(trames_vfs::FileValue::Count(77))));
    assert_eq!(notified.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert!(context.state.lock().unwrap().active.contains(&0x2000));
    disk.complete();
    assert!(context.state.lock().unwrap().active.is_empty());
    assert_eq!(notified.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert!(
        !result.ready(),
        "late native completion cannot publish another close receipt"
    );
    assert!(queue.0.lock().unwrap().is_empty());
}
