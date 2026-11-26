// SPDX-License-Identifier: GPL-3.0-or-later
//! IOCB origins precede payload faults and survive worker/copyout handoffs.
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};

struct Store(std::path::PathBuf);
impl Store {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "trames-aio-origin-{}-{}",
            std::process::id(),
            trames_memory::new_backing_identity()
        )))
    }
}
impl Drop for Store {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[derive(Default)]
struct Queue(Mutex<Vec<(trames_vfs::FileWork, Arc<FileResult>)>>);
impl FileExecutor for Queue {
    fn submit_file(&self, work: trames_vfs::FileWork, result: Arc<FileResult>) {
        self.0.lock().unwrap().push((work.queued(), result));
    }
}
impl Queue {
    fn run(&self) {
        let (work, result) = self.0.lock().unwrap().remove(0);
        std::thread::spawn(move || result.complete(work.run()))
            .join()
            .unwrap();
    }
}
struct Wake;
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn write(v: &mut trames_vfs::Vfs, path: &[u8], bytes: &[u8]) {
    let fd = v.open_at(-100, path, 2, 0).unwrap();
    assert_eq!(v.write(fd, bytes).unwrap(), bytes.len());
    v.close(fd).unwrap();
}
fn text(v: &mut trames_vfs::Vfs, path: &[u8]) -> String {
    let fd = v.open_at(-100, path, 0, 0).unwrap();
    let bytes = v.pread(fd, 4096, 0).unwrap();
    v.close(fd).unwrap();
    String::from_utf8(bytes).unwrap()
}
fn fixture(
    store: &Store,
) -> (
    trames_vfs::Vfs,
    Aio,
    DirectSyscalls,
    Memory,
    Arc<Queue>,
    u64,
) {
    let mut v = trames_vfs::Vfs::open_disk(&store.0, Default::default()).unwrap();
    v.set_runtime_info(1, Default::default());
    v.import_file(
        b"/data",
        [vec![1; 4096], vec![2; 4096], vec![3; 4096]].concat(),
    )
    .unwrap();
    v.import_file(b"/replacement", Vec::new()).unwrap();
    write(
        &mut v,
        b"/sys/fs/cgroup/cgroup.subtree_control",
        b"+memory +io",
    );
    for name in [b"/sys/fs/cgroup/a".as_slice(), b"/sys/fs/cgroup/b"] {
        v.mkdir_at(-100, name, 0o755).unwrap();
    }
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=1 wiops=1");
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    let aio = Aio::default();
    let queue = Arc::new(Queue::default());
    let source = DirectSyscalls::new(v.direct_descriptors())
        .with_membership(v.shared_files())
        .with_resources(v.descriptor_factory())
        .with_aio(aio.clone(), v.native_events())
        .with_paths(v.path_queries())
        .with_file_executor(queue.clone());
    let mut memory = Memory::default();
    memory.map(0x1000, 0x9000, Permissions::RW).unwrap();
    aio.setup([8, 0x1000, 0, 0, 0, 0], &mut memory).unwrap();
    let id = memory.read_u64(0x1000).unwrap();
    (v, aio, source, memory, queue, id)
}
fn iocb(fd: u32, op: u16, address: u64, count: u64) -> [u8; 64] {
    let mut cb = [0; 64];
    cb[..8].copy_from_slice(&123u64.to_le_bytes());
    cb[16..18].copy_from_slice(&op.to_le_bytes());
    cb[20..24].copy_from_slice(&fd.to_le_bytes());
    cb[24..32].copy_from_slice(&address.to_le_bytes());
    cb[32..40].copy_from_slice(&count.to_le_bytes());
    cb
}
fn blocked(attempt: IoAttempt) -> PendingIo {
    let IoAttempt::Blocked(wait) = attempt else {
        panic!("original AIO wait");
    };
    wait
}
#[test]
fn setup_input_fault_preserves_output_allocation_origin_including_native_absence() {
    for pid in [1, 0] {
        let store = Store::new();
        let (mut v, aio, source, mut memory, _, _) = fixture(&store);
        memory.unmap(0x3000, PAGE_SIZE).unwrap();
        let page = file::copyout_tests::install(&mut memory, 0x3000);
        memory.write(0x2ffc, &[0; 4]).unwrap();
        // The handle's first fragment will need a real new COW page, after
        // its second input fragment has waited and the task has migrated.
        let snapshot = memory.try_fork().unwrap();
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let target = Arc::downgrade(&wake);
        let wait = blocked(
            source
                .start(0, [8, 0x2ffc, 0, 0, 0, 0], &mut memory, pid, &target, None)
                .unwrap(),
        );
        assert_eq!(aio.0.contexts.lock().unwrap().len(), 1);
        write(&mut v, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
        let task = v.cgroup_task(1).unwrap();
        let _other = task.resource_scope();
        page.finish();
        assert!(matches!(
            source.resume(wait, &mut memory),
            IoAttempt::Complete(Ok(0))
        ));
        assert_eq!(aio.0.contexts.lock().unwrap().len(), 2);
        assert_eq!(snapshot.read_array::<4>(0x2ffc), Ok([0; 4]));
        assert_eq!(text(&mut v, b"/sys/fs/cgroup/b/memory.current"), "0\n");
        let charged = text(&mut v, b"/sys/fs/cgroup/a/memory.current")
            .trim()
            .parse::<u64>()
            .unwrap();
        if pid == 1 {
            assert!(charged >= PAGE_SIZE);
        } else {
            assert_eq!(charged, 0);
        }
    }
}
#[test]
fn event_copy_wait_keeps_the_reapers_origin_and_cancel_releases_the_consumption_lease() {
    for cancel in [false, true] {
        let store = Store::new();
        let (mut v, aio, source, mut memory, _, id) = fixture(&store);
        memory.unmap(0x3000, PAGE_SIZE).unwrap();
        let page = file::copyout_tests::install(&mut memory, 0x3000);
        memory.write(0x4000, &[0; 16]).unwrap();
        let snapshot = memory.try_fork().unwrap();
        let context = aio.context(id, &memory).unwrap();
        let mut event = [0; 32];
        event[..8].copy_from_slice(&123u64.to_le_bytes());
        event[16..24].copy_from_slice(&17u64.to_le_bytes());
        context.publish(&mut context.state.lock().unwrap(), event);
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let target = Arc::downgrade(&wake);
        let wait = blocked(
            source
                .start(4, [id, 1, 1, 0x3ff0, 0, 0], &mut memory, 1, &target, None)
                .unwrap(),
        );
        assert!(context.state.lock().unwrap().reaping);
        write(&mut v, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
        let task = v.cgroup_task(1).unwrap();
        let _other = task.resource_scope();
        if cancel {
            drop(wait);
            assert_eq!(context.head(), 0);
            assert_eq!(memory.read_array::<16>(0x4000), Ok([0; 16]));
            assert_eq!(text(&mut v, b"/sys/fs/cgroup/a/memory.current"), "0\n");
        } else {
            page.finish();
            assert!(matches!(
                source.resume(wait, &mut memory),
                IoAttempt::Complete(Ok(1))
            ));
            assert_eq!(memory.read_array::<32>(0x3ff0), Ok(event));
            assert_eq!(context.head(), 1);
            assert!(
                text(&mut v, b"/sys/fs/cgroup/a/memory.current")
                    .trim()
                    .parse::<u64>()
                    .unwrap()
                    >= PAGE_SIZE
            );
        }
        assert!(!context.state.lock().unwrap().reaping);
        assert_eq!(snapshot.read_array::<16>(0x4000), Ok([0; 16]));
        assert_eq!(text(&mut v, b"/sys/fs/cgroup/b/memory.current"), "0\n");
    }
}
#[test]
fn a_retired_aio_snapshot_does_not_keep_a_deleted_resource_group_alive() {
    for cancel in [false, true] {
        let store = Store::new();
        let (mut v, aio, source, mut memory, _, id) = fixture(&store);
        // All destination bytes already exist under native ownership. This
        // test isolates the lifetime of the accepted call from physical pages.
        memory.write(0x2000, &[0; 32]).unwrap();
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let target = Arc::downgrade(&wake);
        let wait = blocked(
            source
                .start(4, [id, 1, 1, 0x2000, 0, 0], &mut memory, 1, &target, None)
                .unwrap(),
        );
        let snapshot = wait.aio.clone().unwrap();
        write(&mut v, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
        v.unlink_at(-100, b"/sys/fs/cgroup/a", true).unwrap();
        assert!(text(&mut v, b"/sys/fs/cgroup/cgroup.stat").contains("nr_dying_descendants 1\n"));
        if cancel {
            snapshot.cancel();
            drop(wait);
        } else {
            let context = aio.context(id, &memory).unwrap();
            context.publish(&mut context.state.lock().unwrap(), [0x71; 32]);
            assert!(matches!(
                source.resume(wait, &mut memory),
                IoAttempt::Complete(Ok(1))
            ));
            assert_eq!(memory.read_array::<32>(0x2000), Ok([0x71; 32]));
        }
        assert!(!snapshot.user.as_ref().unwrap().active());
        assert!(text(&mut v, b"/sys/fs/cgroup/cgroup.stat").contains("nr_dying_descendants 0\n"));
        assert!(matches!(
            source.start_retained_aio(snapshot, &mut memory, 1, &target),
            IoAttempt::Complete(Err(Errno(4)))
        ));
    }
}
#[test]
fn aio_payload_wait_keeps_the_accepted_file_and_group_without_inheriting_the_resume_worker() {
    let store = Store::new();
    let (mut v, aio, source, mut memory, queue, id) = fixture(&store);
    let fd = v.open_at(-100, b"/data", 2, 0).unwrap();
    memory.unmap(0x3000, PAGE_SIZE).unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x3000);
    memory.write_array(0x2000, iocb(fd, 1, 0x3000, 7)).unwrap();
    memory.write_array(0x1800, 0x2000u64.to_le_bytes()).unwrap();
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let target = Arc::downgrade(&wake);
    // No ambient task/resource scope: the actual submitting TID still has an
    // authoritative origin in the source DescriptorFactory's cgroup table.
    let wait = blocked(
        source
            .start(2, [id, 1, 0x1800, 0, 0, 0], &mut memory, 1, &target, None)
            .unwrap(),
    );
    assert!(queue.0.lock().unwrap().is_empty());
    write(&mut v, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
    v.close(fd).unwrap();
    assert_eq!(v.open_at(-100, b"/replacement", 2, 0).unwrap(), fd);
    let task = v.cgroup_task(1).unwrap();
    let _other = task.resource_scope();
    page.finish();
    memory.write(0x3000, b"written").unwrap();
    let wait = blocked(source.resume(wait, &mut memory));
    queue.run();
    assert!(matches!(
        source.resume(wait, &mut memory),
        IoAttempt::Complete(Ok(1))
    ));
    let original = v.open_at(-100, b"/data", 0, 0).unwrap();
    assert_eq!(v.pread(original, 7, 0).unwrap(), b"written");
    assert!(v.pread(fd, 7, 0).unwrap().is_empty());
    let a = text(&mut v, b"/sys/fs/cgroup/a/io.stat");
    assert!(a.split_whitespace().any(|word| word == "wios=1"));
    assert!(a.split_whitespace().any(|word| word == "wbytes=7"));
    let b = text(&mut v, b"/sys/fs/cgroup/b/io.stat");
    assert!(!b
        .split_whitespace()
        .any(|word| word.starts_with("wbytes=") && word != "wbytes=0"));
    let context = aio.context(id, &memory).unwrap();
    assert_eq!(context.state.lock().unwrap().tail, 1);
    assert!(context.state.lock().unwrap().active.is_empty());
}
#[test]
fn aio_read_keeps_original_io_memory_and_output_origin_across_later_resource_waits() {
    let store = Store::new();
    let (mut v, aio, source, mut memory, queue, id) = fixture(&store);
    let fd = v.open_at(-100, b"/data", 0, 0).unwrap();
    memory
        .write_array(0x2000, iocb(fd, 0, 0x5000, 12288))
        .unwrap();
    memory.write_array(0x1800, 0x2000u64.to_le_bytes()).unwrap();
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let target = Arc::downgrade(&wake);
    let wait = blocked(
        source
            .start(2, [id, 1, 0x1800, 0, 0, 0], &mut memory, 1, &target, None)
            .unwrap(),
    );
    queue.run();
    let wait = blocked(source.resume(wait, &mut memory));
    assert!(queue.0.lock().unwrap().is_empty());
    assert!(text(&mut v, b"/sys/fs/cgroup/a/io.stat")
        .split_whitespace()
        .any(|word| word == "rios=1"));
    write(&mut v, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=max");
    let task = v.cgroup_task(1).unwrap();
    let _other = task.resource_scope();
    let wait = blocked(source.resume(wait, &mut memory));
    queue.run();
    assert!(matches!(
        source.resume(wait, &mut memory),
        IoAttempt::Complete(Ok(1))
    ));
    assert_eq!(memory.read_array::<1>(0x5000), Ok([1]));
    assert_eq!(memory.read_array::<1>(0x6000), Ok([2]));
    assert_eq!(memory.read_array::<1>(0x7000), Ok([3]));
    let a = text(&mut v, b"/sys/fs/cgroup/a/io.stat");
    assert!(a.split_whitespace().any(|word| word == "rios=3"));
    assert!(a.split_whitespace().any(|word| word == "rbytes=12288"));
    assert!(
        text(&mut v, b"/sys/fs/cgroup/a/memory.current")
            .trim()
            .parse::<u64>()
            .unwrap()
            >= 12288
    );
    assert_eq!(text(&mut v, b"/sys/fs/cgroup/b/memory.current"), "0\n");
    let context = aio.context(id, &memory).unwrap();
    assert_eq!(context.state.lock().unwrap().tail, 1);
    assert!(context.state.lock().unwrap().active.is_empty());
}
#[test]
fn a_native_aio_submitter_does_not_inherit_an_unrelated_workers_guest_limit() {
    let store = Store::new();
    let (mut v, _aio, source, mut memory, queue, id) = fixture(&store);
    let fd = v.open_at(-100, b"/data", 2, 0).unwrap();
    memory.write(0x3000, b"native!").unwrap();
    memory.write_array(0x2000, iocb(fd, 1, 0x3000, 7)).unwrap();
    memory.write_array(0x1800, 0x2000u64.to_le_bytes()).unwrap();
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wbps=1");
    let task = v.cgroup_task(1).unwrap();
    let _unrelated = task.resource_scope();
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let wait = blocked(
        source
            .start(
                2,
                [id, 1, 0x1800, 0, 0, 0],
                &mut memory,
                0,
                &Arc::downgrade(&wake),
                None,
            )
            .unwrap(),
    );
    queue.run();
    assert!(matches!(
        source.resume(wait, &mut memory),
        IoAttempt::Complete(Ok(1))
    ));
    assert_eq!(v.pread(fd, 7, 0).unwrap(), b"native!");
    let a = text(&mut v, b"/sys/fs/cgroup/a/io.stat");
    assert!(!a
        .split_whitespace()
        .any(|word| word.starts_with("wbytes=") && word != "wbytes=0"));
}
