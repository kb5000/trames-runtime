// SPDX-License-Identifier: GPL-3.0-or-later
//! Original read/readv ABI, resource ownership and partial output survive waits.
use super::*;

struct Store(std::path::PathBuf);
impl Store {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "trames-read-copyout-{}-{}",
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
fn write(v: &mut trames_vfs::Vfs, path: &[u8], bytes: &[u8]) {
    let fd = v.open_at(-100, path, 2, 0).unwrap();
    assert_eq!(v.write(fd, bytes).unwrap(), bytes.len());
    v.close(fd).unwrap();
}
fn setup(store: &Store) -> (trames_vfs::Vfs, u32) {
    let mut v = trames_vfs::Vfs::open_disk(&store.0, Default::default()).unwrap();
    v.set_runtime_info(1, Default::default());
    v.import_file(
        b"/data",
        [vec![1; 4096], vec![2; 4096], vec![3; 4096]].concat(),
    )
    .unwrap();
    v.import_file(b"/other", b"other inode".to_vec()).unwrap();
    write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"+io");
    v.mkdir_at(-100, b"/sys/fs/cgroup/a", 0o755).unwrap();
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=1");
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    let fd = v.open_at(-100, b"/data", 0, 0).unwrap();
    (v, fd)
}
fn pending(attempt: IoAttempt) -> FilePending {
    let IoAttempt::Blocked(wait) = attempt else {
        panic!("expected original file wait");
    };
    wait.file_pending().unwrap()
}
fn run_one(queue: &std::sync::mpsc::Receiver<(trames_vfs::FileWork, Arc<FileResult>)>) {
    let (work, result) = queue.recv_timeout(Duration::from_secs(2)).unwrap();
    std::thread::spawn(move || result.complete(work.run()))
        .join()
        .unwrap();
}
#[test]
fn read_and_readv_resume_after_io_wait_then_commit_only_successful_guest_copyout() {
    for owned in [false, true] {
        for vectors in [false, true] {
            let store = Store::new();
            let (mut v, fd) = setup(&store);
            let alias = v.dup(fd, 0, false).unwrap();
            let mut memory = Memory::default();
            memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
            memory.map(0x10000, 3 * PAGE_SIZE, Permissions::RW).unwrap();
            memory.write(0x10000, &vec![0xcc; 12288]).unwrap();
            for (address, word) in [
                (0x1000, 0x10000u64),
                (0x1008, 4096),
                (0x1010, 0x11000),
                (0x1018, 8192),
            ] {
                memory.write_array(address, word.to_le_bytes()).unwrap();
            }
            let number = if vectors { 65 } else { 63 };
            let args = [
                fd as u64,
                if vectors { 0x1000 } else { 0x10000 },
                if vectors { 2 } else { 12288 },
                0,
                0,
                0,
            ];
            let (send, queue) = std::sync::mpsc::channel();
            let executor: Arc<dyn FileExecutor> = Arc::new(Queue(send));
            let mut epoch = trames_vfs::FileEpoch::default();
            let direct = DirectSyscalls::default().with_file_executor(executor.clone());
            let direct = if owned {
                direct
            } else {
                direct
                    .with_files(epoch.capture(&v, true))
                    .with_membership(v.shared_files())
                    .with_paths(v.path_queries())
            };
            let target = t();
            let task = v.cgroup_task(1).unwrap();
            let resources = task.resource_scope();
            let first = if owned {
                direct.start_owned_file(
                    &mut v,
                    number,
                    args,
                    &mut memory,
                    1,
                    &Arc::downgrade(&target),
                )
            } else {
                direct.start_file_call(number, args, &mut memory, 1, &Arc::downgrade(&target))
            };
            let original = pending(first.unwrap());
            let original = if owned {
                // A short joined read runs on its caller, then parks directly
                // on the first genuine resource wait without entering a pool.
                original
            } else {
                run_one(&queue);
                pending(direct.start_retained_file(
                    original,
                    number,
                    args,
                    &mut memory,
                    1,
                    &Arc::downgrade(&target),
                ))
            };
            assert!(
                queue.try_recv().is_err(),
                "an IO deadline parks the existing request"
            );
            assert_eq!(
                v.seek(alias, 0, 1),
                Err(Errno(11)),
                "the original position is retained"
            );
            assert_eq!(memory.read_array::<1>(0x10000), Ok([0xcc]));
            write(&mut v, b"/sys/fs/cgroup/cgroup.procs", b"1");
            drop(resources);
            let writer = v.open_at(-100, b"/data", 2, 0).unwrap();
            v.pwrite(writer, &[99], 0).unwrap();
            v.close(writer).unwrap();
            v.close(fd).unwrap();
            assert_eq!(v.open_at(-100, b"/other", 0, 0).unwrap(), fd);
            if vectors {
                memory
                    .write_array(0x1000, 0xdead0000u64.to_le_bytes())
                    .unwrap();
                memory
                    .write_array(0x1010, 0xbeef0000u64.to_le_bytes())
                    .unwrap();
            }
            drop(direct);
            epoch.finish();
            write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=max");
            let resumed = DirectSyscalls::default().with_file_executor(executor);
            let original = pending(resumed.start_retained_file(
                original,
                number,
                args,
                &mut memory,
                1,
                &Arc::downgrade(&target),
            ));
            run_one(&queue);
            // The original destination passed admission. A later real copyout
            // fault must publish only the first copied page to the old OFD.
            memory.unmap(0x11000, PAGE_SIZE).unwrap();
            assert!(matches!(
                resumed.start_retained_file(
                    original,
                    number,
                    args,
                    &mut memory,
                    1,
                    &Arc::downgrade(&target)
                ),
                IoAttempt::Complete(Ok(4096))
            ));
            assert_eq!(
                memory.read_array::<1>(0x10000),
                Ok([1]),
                "the completed read prefix is retained"
            );
            assert_eq!(memory.read_array::<1>(0x12000), Ok([0xcc]));
            assert_eq!(v.seek(alias, 0, 1), Ok(4096));
            assert_eq!(v.seek(fd, 0, 1), Ok(0));
            let stats = v.open_at(-100, b"/sys/fs/cgroup/a/io.stat", 0, 0).unwrap();
            let stats = String::from_utf8(v.pread(stats, 4096, 0).unwrap()).unwrap();
            assert!(stats.split_whitespace().any(|word| word == "rios=3"));
            assert!(stats.split_whitespace().any(|word| word == "rbytes=12288"));
        }
    }
}
#[test]
fn a_parked_guest_read_signal_returns_its_original_prefix_without_resubmitting_disk_work() {
    for prefix in [false, true] {
        let store = Store::new();
        let (mut v, fd) = setup(&store);
        if !prefix {
            write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 rbps=1");
        }
        let mut memory = Memory::default();
        memory.map(0x10000, 3 * PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x10000, &vec![0xcc; 12288]).unwrap();
        let (send, queue) = std::sync::mpsc::channel();
        let direct = DirectSyscalls::default()
            .with_membership(v.shared_files())
            .with_paths(v.path_queries())
            .with_file_executor(Arc::new(Queue(send)));
        let target = t();
        let task = v.cgroup_task(1).unwrap();
        let resources = task.resource_scope();
        let args = [fd as u64, 0x10000, 12288, 0, 0, 0];
        let original = pending(
            direct
                .start_file_call(63, args, &mut memory, 1, &Arc::downgrade(&target))
                .unwrap(),
        );
        run_one(&queue);
        let original = pending(direct.start_retained_file(
            original,
            63,
            args,
            &mut memory,
            1,
            &Arc::downgrade(&target),
        ));
        assert!(original.interruptible());
        assert_eq!(
            original.interrupted(&mut memory),
            Some(if prefix { Ok(4096) } else { Err(Errno(4)) })
        );
        assert!(queue.try_recv().is_err());
        assert_eq!(
            memory.read_array::<1>(0x10000),
            Ok([if prefix { 1 } else { 0xcc }])
        );
        assert_eq!(memory.read_array::<1>(0x11000), Ok([0xcc]));
        drop(original);
        drop(resources);
        assert_eq!(v.seek(fd, 0, 1), Ok(if prefix { 4096 } else { 0 }));
    }
}
