// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};
struct Queue(std::sync::mpsc::Sender<(trames_vfs::FileWork, Arc<FileResult>)>);
impl FileExecutor for Queue {
    fn submit_file(&self, work: trames_vfs::FileWork, result: Arc<FileResult>) {
        result.begin();
        assert!(self.0.send((work.queued(), result)).is_ok());
    }
}
#[derive(Default)]
struct Target(std::sync::atomic::AtomicUsize);
impl IoWake for Target {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
fn t() -> Arc<dyn IoWake> {
    Arc::new(Target::default())
}
fn disk() -> (std::path::PathBuf, trames_vfs::Vfs) {
    let path = std::env::temp_dir().join(format!(
        "trames-accepted-file-{}-{}",
        std::process::id(),
        trames_memory::new_backing_identity()
    ));
    let v = trames_vfs::Vfs::open_disk(&path, Default::default()).unwrap();
    (path, v)
}
#[test]
fn imported_write_survives_epoch_drop_input_changes_fd_reuse_and_native_completion() {
    let (path, mut v) = disk();
    v.import_file(b"/old", Vec::new()).unwrap();
    v.import_file(b"/other", b"untouched".to_vec()).unwrap();
    let fd = v.open_at(-100, b"/old", 2, 0).unwrap();
    let mut memory = Memory::default();
    memory.map(0x10000, 8 * PAGE_SIZE, Permissions::RW).unwrap();
    memory.write(0x10000, &vec![0xa5; 32768]).unwrap();
    let mut epoch = trames_vfs::FileEpoch::default();
    let caps = epoch.capture(&v, true);
    let (send, receive) = std::sync::mpsc::channel();
    let old_target = t();
    let direct = DirectSyscalls::default()
        .with_files(caps)
        .with_membership(v.shared_files())
        .with_paths(v.path_queries())
        .with_file_executor(Arc::new(Queue(send)));
    let args = [fd as u64, 0x10000, 32768, 0, 0, 0];
    let Some(IoAttempt::Blocked(wait)) =
        direct.start_file_call(64, args, &mut memory, 1, &Arc::downgrade(&old_target))
    else {
        panic!("native write should release its CPU slot");
    };
    let pending = wait.file_pending().unwrap();
    drop(wait);
    drop((direct, old_target));
    epoch.finish();
    memory.write(0x10000, &vec![0x33; 32768]).unwrap();
    v.close(fd).unwrap();
    assert_eq!(v.open_at(-100, b"/other", 2, 0).unwrap(), fd);
    let new_target = t();
    let direct = DirectSyscalls::default();
    let IoAttempt::Blocked(wait) = direct.start_retained_file(
        pending,
        64,
        args,
        &mut memory,
        1,
        &Arc::downgrade(&new_target),
    ) else {
        panic!("original native result is not ready");
    };
    let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    std::thread::spawn(move || result.complete(work.run()))
        .join()
        .unwrap();
    assert!(wait.signal.ready());
    let pending = wait.file_pending().unwrap();
    drop(wait);
    assert!(matches!(
        direct.start_retained_file(
            pending,
            64,
            args,
            &mut memory,
            1,
            &Arc::downgrade(&new_target)
        ),
        IoAttempt::Complete(Ok(32768))
    ));
    let original = v.open_at(-100, b"/old", 0, 0).unwrap();
    assert_eq!(v.read(original, 32768).unwrap(), vec![0xa5; 32768]);
    assert_eq!(v.pread(fd, 32, 0).unwrap(), b"untouched");
    drop((direct, v));
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn all_vector_destinations_are_checked_before_native_read_advances_the_original_offset() {
    let (path, mut v) = disk();
    v.import_file(b"/data", vec![0xa5; 32768]).unwrap();
    let fd = v.open_at(-100, b"/data", 2, 0).unwrap();
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    for (a, n) in [
        (0x10000, 0x10100u64),
        (0x10008, 2),
        (0x10010, 0x20000),
        (0x10018, 2),
    ] {
        memory.write_array(a, n.to_le_bytes()).unwrap();
    }
    let mut epoch = trames_vfs::FileEpoch::default();
    let caps = epoch.capture(&v, true);
    let (send, receive) = std::sync::mpsc::channel();
    let direct = DirectSyscalls::default()
        .with_files(caps)
        .with_membership(v.shared_files())
        .with_paths(v.path_queries())
        .with_file_executor(Arc::new(Queue(send)));
    assert!(matches!(
        direct.start_file_call(
            65,
            [fd as u64, 0x10000, 2, 0, 0, 0],
            &mut memory,
            1,
            &Arc::downgrade(&t())
        ),
        Some(IoAttempt::Complete(Err(Errno(14))))
    ));
    assert!(receive.try_recv().is_err());
    assert_eq!(v.seek(fd, 0, 1), Ok(0));
    drop((direct, v));
    epoch.finish();
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn finite_file_limit_returns_partial_progress_then_one_original_signal_boundary() {
    let mut v = trames_vfs::Vfs::default();
    v.import_file(b"/data", Vec::new()).unwrap();
    let fd = v.open_at(-100, b"/data", 2, 0).unwrap();
    v.set_file_size_limit(4);
    let mut epoch = trames_vfs::FileEpoch::default();
    let caps = epoch.capture(&v, false);
    let direct = DirectSyscalls::default()
        .with_files(caps)
        .with_membership(v.shared_files())
        .with_paths(v.path_queries());
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.write(0x10000, b"12345678").unwrap();
    let args = [fd as u64, 0x10000, 8, 0, 0, 0];
    let target = t();
    assert!(matches!(
        direct.start_file_call(64, args, &mut memory, 1, &Arc::downgrade(&target)),
        Some(IoAttempt::Complete(Ok(4)))
    ));
    let Some(IoAttempt::FileCheckpoint(checkpoint)) =
        direct.start_file_call(64, args, &mut memory, 1, &Arc::downgrade(&target))
    else {
        panic!("SIGXFSZ task transition");
    };
    assert!(matches!(
        checkpoint.take(),
        FileBoundary::Signal {
            value: Err(Errno(27))
        }
    ));
    assert_eq!(v.pread(fd, 32, 0).unwrap(), b"1234");
    assert!(!v.take_file_size_signal());
    epoch.finish();
}
#[test]
fn source_file_copy_preserves_explicit_offsets_and_implicit_cursors() {
    let mut v = trames_vfs::Vfs::default();
    v.import_file(b"/source", b"abcdef".to_vec()).unwrap();
    v.import_file(b"/target", Vec::new()).unwrap();
    let a = v.open_at(-100, b"/source", 2, 0).unwrap();
    let b = v.open_at(-100, b"/target", 2, 0).unwrap();
    let mut epoch = trames_vfs::FileEpoch::default();
    let caps = epoch.capture(&v, true);
    let (send, receive) = std::sync::mpsc::channel();
    let direct = DirectSyscalls::default()
        .with_files(caps)
        .with_membership(v.shared_files())
        .with_paths(v.path_queries())
        .with_file_executor(Arc::new(Queue(send)));
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.write_array(0x10000, 1u64.to_le_bytes()).unwrap();
    memory.write_array(0x10008, 2u64.to_le_bytes()).unwrap();
    let args = [a as u64, 0x10000, b as u64, 0x10008, 3, 0];
    let target = t();
    let Some(IoAttempt::Blocked(wait)) =
        direct.start_file_call(285, args, &mut memory, 1, &Arc::downgrade(&target))
    else {
        panic!("accepted file copy");
    };
    let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    result.complete(work.run());
    let pending = wait.file_pending().unwrap();
    drop(wait);
    assert!(matches!(
        direct.start_retained_file(pending, 285, args, &mut memory, 1, &Arc::downgrade(&target)),
        IoAttempt::Complete(Ok(3))
    ));
    assert_eq!(memory.read_u64(0x10000).unwrap(), 4);
    assert_eq!(memory.read_u64(0x10008).unwrap(), 5);
    assert_eq!(v.pread(b, 32, 0).unwrap(), b"\0\0bcd");
    assert_eq!(v.seek(a, 0, 1).unwrap(), 0);
    assert_eq!(v.seek(b, 0, 1).unwrap(), 0);
    epoch.finish();
}

#[test]
fn pathname_truncate_retains_the_resolved_file_and_imported_path_through_native_wait() {
    let (directory, mut v) = disk();
    v.import_file(b"/file", b"original".to_vec()).unwrap();
    let fd = v.open_at(-100, b"/file", 2, 0).unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let direct = DirectSyscalls::default()
        .with_paths(v.path_queries())
        .with_file_executor(Arc::new(Queue(send)));
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.write(0x10000, b"/file\0").unwrap();
    let args = [0x10000, 3, 0, 0, 0, 0];
    let target = t();
    let Some(IoAttempt::Blocked(wait)) =
        direct.start_file_call(45, args, &mut memory, 1, &Arc::downgrade(&target))
    else {
        panic!("accepted pathname truncate");
    };
    memory.write(0x10000, b"/other\0").unwrap();
    v.rename_at(-100, b"/file", -100, b"/old", 0).unwrap();
    v.import_file(b"/file", b"replacement".to_vec()).unwrap();
    let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    result.complete(work.run());
    let pending = wait.file_pending().unwrap();
    drop(wait);
    assert!(matches!(
        direct.start_retained_file(pending, 45, args, &mut memory, 1, &Arc::downgrade(&target)),
        IoAttempt::Complete(Ok(0))
    ));
    assert_eq!(v.pread(fd, 32, 0).unwrap(), b"ori");
    let replacement = v.open_at(-100, b"/file", 0, 0).unwrap();
    assert_eq!(replacement, fd + 1);
    assert_eq!(v.read(replacement, 32).unwrap(), b"replacement");
    drop((direct, v));
    std::fs::remove_dir_all(directory).unwrap();
}
