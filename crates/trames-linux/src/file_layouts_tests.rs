// SPDX-License-Identifier: GPL-3.0-or-later
//! Actual executor retirement while a FUSE notification owns its completion.
use super::*;
use trames_vfs::{
    FileCommand, FileEpoch, FileOutcome, FileValue, Vfs, AT_FDCWD, O_DIRECTORY, O_PATH,
};

type Host = (Box<dyn HostFileTask>, Option<crate::HostFileAdmission>);
#[derive(Default)]
struct Queue(Mutex<Vec<Host>>);
struct AdmissionTask {
    layout: Arc<Layout>,
    owner: trames_memory::MemoryReport,
    ran: Arc<std::sync::atomic::AtomicBool>,
}
impl HostFileTask for AdmissionTask {
    fn layout(&self) -> Option<Arc<Layout>> {
        Some(self.layout.clone())
    }
    fn run(self: Box<Self>, admission: Option<crate::HostFileAdmission>) {
        let admission = admission.expect("original layout exclusion");
        assert_eq!(admission.layout().identity(), self.layout.identity());
        assert!(
            self.layout.try_read(self.owner.clone()).is_none(),
            "a new publication cannot overtake accepted host work"
        );
        self.ran.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    fn fail(self: Box<Self>) {
        panic!("accepted task was not retired");
    }
}

#[test]
fn unmapped_host_work_uses_the_existing_pool_with_original_publication_exclusion() {
    let queue = Arc::new(Queue::default());
    let layouts = FileLayouts::new(queue.clone());
    let layout = Arc::new(Layout::default());
    let memory = trames_memory::Memory::default();
    let owner = memory.memory_report();
    let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
    layouts.submit_host(Box::new(AdmissionTask {
        layout: layout.clone(),
        owner: owner.clone(),
        ran: ran.clone(),
    }));
    assert!(!layouts.pending(), "no reader requires a driver checkpoint");
    assert_eq!(queue.0.lock().unwrap().len(), 1);
    assert!(layout.try_read(owner.clone()).is_none());
    queue.run(&layouts);
    assert!(ran.load(std::sync::atomic::Ordering::Relaxed));
    assert!(layout.try_read(owner).is_some());
}

#[test]
fn mapped_host_work_keeps_readiness_wait_and_original_lease_until_the_last_reader_leaves() {
    let queue = Arc::new(Queue::default());
    let layouts = FileLayouts::new(queue.clone());
    let layout = Arc::new(Layout::default());
    let memory = trames_memory::Memory::default();
    let owner = memory.memory_report();
    let reader = layout.try_read(owner.clone()).unwrap();
    let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
    layouts.submit_host(Box::new(AdmissionTask {
        layout: layout.clone(),
        owner: owner.clone(),
        ran: ran.clone(),
    }));
    assert!(layouts.pending());
    assert!(queue.0.lock().unwrap().is_empty());
    let request = layouts.take_owner().pop().unwrap();
    let request = match layouts.try_submit(request) {
        Err(request) => request,
        Ok(()) => panic!("original reader is still live"),
    };
    assert!(layout.try_read(owner.clone()).is_none());
    drop(reader);
    assert!(layouts.try_submit(request).is_ok());
    queue.run(&layouts);
    assert!(ran.load(std::sync::atomic::Ordering::Relaxed));
    assert!(layout.try_read(owner).is_some());
}
impl FileExecutor for Queue {
    fn submit_file(&self, _: FileWork, _: Arc<FileResult>) {
        panic!("no file replay")
    }
    fn submit_host(&self, job: Box<dyn HostFileTask>, admission: Option<crate::HostFileAdmission>) {
        self.0.lock().unwrap().push((job, admission));
    }
}
impl Queue {
    fn run(&self, layouts: &FileLayouts) {
        for request in layouts.take_owner() {
            assert!(layouts.try_submit(request).is_ok());
        }
        let mut jobs = std::mem::take(&mut *self.0.lock().unwrap());
        assert_eq!(jobs.len(), 1);
        let (job, admission) = jobs.pop().unwrap();
        job.run(admission);
    }
}
fn packet(unique: u64, code: i32, body: &[u8]) -> Vec<u8> {
    let mut bytes = ((16 + body.len()) as u32).to_le_bytes().to_vec();
    bytes.extend(code.to_le_bytes());
    bytes.extend(unique.to_le_bytes());
    bytes.extend(body);
    bytes
}
fn answer(c: &trames_vfs::DirectFd, request: &[u8], body: &[u8]) {
    let unique = u64::from_le_bytes(request[8..16].try_into().unwrap());
    c.write(&packet(unique, 0, body)).unwrap();
}
fn receive(c: &trames_vfs::DirectFd, opcode: u32, node: u64) -> Vec<u8> {
    let request = c.read(8192).unwrap();
    assert_eq!(&request[4..8], &opcode.to_le_bytes());
    assert_eq!(&request[16..24], &node.to_le_bytes());
    request
}
fn entry(node: u64, mode: u32) -> [u8; 128] {
    let mut bytes = [0; 128];
    bytes[..8].copy_from_slice(&node.to_le_bytes());
    bytes[24..32].copy_from_slice(&1u64.to_le_bytes());
    bytes[40..48].copy_from_slice(&(node + 100).to_le_bytes());
    bytes[100..104].copy_from_slice(&mode.to_le_bytes());
    bytes
}
fn waiting(work: FileWork) -> FileWork {
    match work.run() {
        FileOutcome::Waiting(work) => work,
        _ => panic!("original resource wait"),
    }
}
fn finished(work: FileWork) -> Result<FileValue, trames_vfs::Errno> {
    match work.run() {
        FileOutcome::Complete(reply) => reply.result,
        _ => panic!("completed original call"),
    }
}

#[test]
fn retiring_the_real_executor_finishes_a_parked_fuse_notification_and_releases_its_writer_wait() {
    let mut v = Vfs::default();
    v.set_runtime_info(1, Default::default());
    v.mkdir_at(AT_FDCWD, b"/mnt", 0o755).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/dev/fuse", 2, 0).unwrap();
    let options = format!("fd={fd},rootmode=40755,user_id=0,group_id=0");
    v.mount(None, b"/mnt", Some(b"fuse"), 0, Some(options.as_bytes()))
        .unwrap();
    let transport = v
        .shared_files()
        .lookup(fd)
        .unwrap()
        .unwrap()
        .direct_byte()
        .unwrap();
    let c = &transport;
    let init = receive(c, 26, 0);
    let mut version = [0; 64];
    version[..4].copy_from_slice(&7u32.to_le_bytes());
    version[4..8].copy_from_slice(&31u32.to_le_bytes());
    answer(c, &init, &version);
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(
            AT_FDCWD,
            b"/mnt/directory",
            O_PATH | O_DIRECTORY,
            0,
            0,
            &files
        )
        .is_none());
    let open = paths.take_open_work().unwrap();
    answer(c, &receive(c, 1, 1), &entry(70, 0o40755));
    let FileValue::Count(directory) = finished(open).unwrap() else {
        panic!("directory FD")
    };
    assert!(paths.statx_at(directory as i32, b"first", false).is_none());
    let first = paths.take_fuse_stat().unwrap();
    let lookup = receive(c, 1, 70);

    let queue = Arc::new(Queue::default());
    let layouts = FileLayouts::new(queue.clone());
    let mut body = 70u64.to_le_bytes().to_vec();
    body.extend(5u32.to_le_bytes());
    body.extend(0u32.to_le_bytes());
    body.extend(b"first\0");
    let target = v
        .shared_files()
        .lookup(fd)
        .unwrap()
        .unwrap()
        .filesystem_target();
    let notification = {
        let _actor = trames_vfs::FileActorScope::enter_with_sync(
            Arc::new(trames_vfs::CredentialState::new(v.credentials.clone())),
            1,
            Some(layouts.sync_executor()),
        );
        waiting(FileWork::new(
            &paths,
            target,
            FileCommand::Write {
                bytes: packet(0, 3, &body),
                offset: None,
            },
        ))
    };
    queue.run(&layouts);
    assert!(!notification.ready());
    assert!(queue.0.lock().unwrap().is_empty() && !layouts.pending());
    assert!(paths.statx_at(directory as i32, b"second", false).is_none());
    let second = waiting(paths.take_fuse_stat().unwrap());
    assert!(!second.ready());
    assert_eq!(c.read(8192), Err(trames_vfs::Errno(11)));
    struct Wake;
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let reader_signal = IoSignal::new(2, Arc::downgrade(&wake));
    let device_signal = IoSignal::new(1, Arc::downgrade(&wake));
    let _reader_wait = second.wait_sources(&reader_signal).unwrap();
    let _device_wait = notification.wait_sources(&device_signal).unwrap();

    let retired = Arc::downgrade(&layouts);
    drop(layouts);
    assert!(retired.upgrade().is_none());
    assert!(reader_signal.ready() && device_signal.ready());
    assert!(notification.ready());
    assert!(matches!(finished(notification), Err(trames_vfs::Errno(5))));
    assert!(
        second.ready(),
        "cancelled writer intent releases the new reader"
    );
    let second = waiting(second);
    let next_lookup = receive(c, 1, 70);
    assert_eq!(&next_lookup[40..], b"second\0");
    answer(c, &lookup, &entry(71, 0o100644));
    answer(c, &next_lookup, &entry(72, 0o100644));
    assert!(matches!(finished(first), Ok(FileValue::FuseStat(..))));
    assert!(matches!(finished(second), Ok(FileValue::FuseStat(..))));
    assert!(
        queue.0.lock().unwrap().is_empty(),
        "retirement never requeues the accepted notification"
    );
}

#[test]
fn retiring_layout_admission_fails_a_queued_sync_once_without_running_its_provider() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use trames_memory::{MemoryError, SyncCompletion, SyncResource};
    struct Resource {
        layout: Arc<Layout>,
        calls: AtomicUsize,
        errors: AtomicUsize,
    }
    impl SyncResource for Resource {
        fn layout(&self) -> Option<Arc<Layout>> {
            Some(self.layout.clone())
        }
        fn sync(&self) -> Result<(), MemoryError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn failed(&self, _: MemoryError) {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
    }
    struct Complete(Arc<Mutex<Vec<Result<(), MemoryError>>>>);
    impl SyncCompletion for Complete {
        fn complete(self: Box<Self>, result: Result<(), MemoryError>) {
            self.0.lock().unwrap().push(result);
        }
    }
    for admitted in [false, true] {
        let queue = Arc::new(Queue::default());
        let layouts = FileLayouts::new(queue.clone());
        let resource = Arc::new(Resource {
            layout: Arc::default(),
            calls: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
        });
        let completed = Arc::new(Mutex::new(Vec::new()));
        let memory = trames_memory::Memory::default();
        let reader = resource.layout.try_read(memory.memory_report()).unwrap();
        layouts
            .sync_executor()
            .submit(resource.clone(), Box::new(Complete(completed.clone())));
        assert!(layouts.pending());
        if admitted {
            drop(reader);
            for request in layouts.take_owner() {
                assert!(layouts.try_submit(request).is_ok());
            }
        }
        drop(layouts);
        if admitted {
            let (job, admission) = queue.0.lock().unwrap().pop().unwrap();
            job.run(admission);
        }
        assert_eq!(
            completed.lock().unwrap().as_slice(),
            &[if admitted {
                Ok(())
            } else {
                Err(MemoryError::BackingIo(5))
            }]
        );
        assert_eq!(
            resource.calls.load(Ordering::Relaxed),
            usize::from(admitted)
        );
        assert_eq!(
            resource.errors.load(Ordering::Relaxed),
            usize::from(!admitted)
        );
        assert!(queue.0.lock().unwrap().is_empty());
    }
}
