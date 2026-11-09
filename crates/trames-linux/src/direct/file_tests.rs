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
#[test]
fn native_memfd_creation_retains_original_name_files_credentials_and_handoff() {
    let mut v = trames_vfs::Vfs::default();
    v.credentials = trames_vfs::Credentials::user(1000, 1001);
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.write(0x1000, b"original\0").unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let target = t();
    let direct = DirectSyscalls::default()
        .with_paths(v.path_queries())
        .with_file_executor(Arc::new(Queue(send)));
    let args = [0x1000, 3, 0, 0, 0, 0];
    let Some(IoAttempt::Blocked(wait)) =
        direct.start_file_call(279, args, &mut memory, 1, &Arc::downgrade(&target))
    else {
        panic!("native memory-file allocation must return its CPU slot")
    };
    let pending = wait.file_pending().unwrap();
    assert!(!pending.interruptible());
    drop((wait, direct, target));
    memory.unmap(0x1000, PAGE_SIZE).unwrap();
    v.credentials = Default::default();
    let original_counter = v.eventfd(99, 0).unwrap();
    let mut unrelated = trames_vfs::Vfs::default();
    assert_eq!(
        unrelated.memfd_create(b"unrelated", 0).unwrap(),
        original_counter
    );
    let target = t();
    let IoAttempt::Blocked(wait) = DirectSyscalls::default().start_retained_file(
        pending,
        279,
        args,
        &mut memory,
        1,
        &Arc::downgrade(&target),
    ) else {
        panic!("retain accepted native allocation")
    };
    let pending = wait.file_pending().unwrap();
    let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    std::thread::spawn(move || result.complete(work.run()))
        .join()
        .unwrap();
    assert!(wait.signal.ready());
    drop(wait);
    let IoAttempt::Complete(Ok(fd)) = DirectSyscalls::default().start_retained_file(
        pending,
        279,
        args,
        &mut memory,
        1,
        &Arc::downgrade(&target),
    ) else {
        panic!("commit accepted original memory file")
    };
    let fd = fd as u32;
    assert_ne!(fd, original_counter);
    assert_eq!(
        v.fd_kind(fd).unwrap(),
        trames_vfs::FdKind::Node(b"/memfd:original".to_vec())
    );
    assert_eq!(v.flags(fd).unwrap(), 2 | trames_vfs::O_CLOEXEC);
    assert_eq!(v.seals(fd, None), Ok(0));
    let stat = v.stat_fd(fd).unwrap();
    assert_eq!(u32::from_le_bytes(stat[24..28].try_into().unwrap()), 1000);
    assert_eq!(u32::from_le_bytes(stat[28..32].try_into().unwrap()), 1001);
    assert_eq!(v.read(original_counter, 8).unwrap(), 99u64.to_le_bytes());
    assert!(unrelated.flags(fd).is_err());
}
#[test]
fn memfd_source_solo_import_and_allocation_errors_share_original_ordering() {
    let mut linux = Linux::new(0x100000);
    linux.vfs.set_descriptor_limit(3);
    let mut memory = Memory::default();
    memory.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
    let target = t();
    let (send, receive) = std::sync::mpsc::channel();
    let direct = DirectSyscalls::default()
        .with_paths(linux.vfs.path_queries())
        .with_file_executor(Arc::new(Queue(send)));
    for (address, flags, name, expected) in [
        (0x9000, 4, Vec::new(), 14),
        (0x1000, 4, b"valid\0".to_vec(), 22),
        (0x1000, 0, [vec![b'x'; 250], vec![0]].concat(), 22),
        (0x1000, 0, vec![b'x'; 4096], 36),
        (0x1000, 0, b"valid\0".to_vec(), 24),
    ] {
        if !name.is_empty() {
            memory.write(0x1000, &name).unwrap();
        }
        let args = [address, flags, 0, 0, 0, 0];
        assert_eq!(
            linux.syscall(
                279,
                args,
                &mut memory,
                &mut crate::CapturedOutput::default()
            ),
            Err(Errno(expected))
        );
        let attempt = direct
            .start_file_call(279, args, &mut memory, 1, &Arc::downgrade(&target))
            .unwrap();
        let attempt = match attempt {
            IoAttempt::Blocked(wait) => {
                let pending = wait.file_pending().unwrap();
                let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
                result.complete(work.run());
                drop(wait);
                DirectSyscalls::default().start_retained_file(
                    pending,
                    279,
                    args,
                    &mut memory,
                    1,
                    &Arc::downgrade(&target),
                )
            }
            value => value,
        };
        assert!(matches!(attempt,IoAttempt::Complete(Err(Errno(e))) if e==expected));
        assert!(receive.try_recv().is_err());
    }
    assert!(DirectSyscalls::default()
        .start_file_call(279, [0; 6], &mut memory, 1, &Arc::downgrade(&target))
        .is_none());
}
#[test]
fn mapped_write_seal_parks_and_keeps_its_original_inode_through_close_and_fd_reuse() {
    for cancel in [false, true] {
        let mut v = trames_vfs::Vfs::default();
        let fd = v.memfd_create(b"original", 2).unwrap();
        v.write(fd, b"original bytes").unwrap();
        let alias = v.dup(fd, 0, false).unwrap();
        // A private read-only mapping keeps backing without VM_MAYWRITE.
        // Shared mappings of O_RDWR prevent WRITE seals even while read-only.
        let pages = v.mapping_pages(fd, 0, PAGE_SIZE, false, false).unwrap();
        let mut memory = Memory::default();
        memory
            .map_backed(0x10000, pages, false, Permissions::R, false)
            .unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let target = t();
        let direct = DirectSyscalls::default()
            .with_resources(v.descriptor_factory())
            .with_paths(v.path_queries())
            .with_file_executor(Arc::new(Queue(send)));
        let args = [fd as u64, 1033, 8, 0, 0, 0];
        let Some(IoAttempt::Blocked(wait)) =
            direct.start_file_call(25, args, &mut memory, 1, &Arc::downgrade(&target))
        else {
            panic!("native seal sync must release its execution slot")
        };
        let pending = wait.file_pending().unwrap();
        drop(wait);
        v.close(fd).unwrap();
        assert_eq!(v.memfd_create(b"replacement", 2).unwrap(), fd);
        drop(direct);
        let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
        if cancel {
            drop(pending);
        } else {
            std::thread::spawn(move || result.complete(work.run()))
                .join()
                .unwrap();
            assert!(matches!(
                DirectSyscalls::default().start_retained_file(
                    pending,
                    25,
                    args,
                    &mut memory,
                    1,
                    &Arc::downgrade(&target)
                ),
                IoAttempt::Complete(Ok(0))
            ));
            assert_eq!(v.seals(alias, None), Ok(8));
            assert_eq!(v.pwrite(alias, b"changed", 0), Err(Errno(1)));
            assert_eq!(v.pread(alias, 32, 0).unwrap(), b"original bytes");
            assert_eq!(v.seals(fd, None), Ok(0));
            continue;
        }
        // Once accepted by the existing disk pool, cancellation may leave
        // the real inode effect, but must never redirect it to a reused FD.
        result.complete(work.run());
        assert_eq!(v.seals(alias, None), Ok(8));
        assert_eq!(v.seals(fd, None), Ok(0));
    }
}
#[test]
fn mmap_plan_waits_before_page_preparation_and_retains_original_fd() {
    let mut linux = Linux::new(0x100000);
    linux
        .vfs
        .import_file(b"/original", b"original bytes".to_vec())
        .unwrap();
    linux
        .vfs
        .import_file(b"/other", b"replacement".to_vec())
        .unwrap();
    let fd = linux.vfs.open_at(-100, b"/original", 2, 0).unwrap();
    let mut memory = Memory::default();
    let args = [0x4000, PAGE_SIZE, 3, 0x12, fd as u64, 0];
    let mut plan = linux.prepare_mmap(args, &memory).unwrap();
    let layout = plan.layout().unwrap().clone();
    let exclusive = layout.write().try_enter().ok().unwrap();
    assert!(!plan.try_admit(memory.memory_report()));
    assert!(memory.is_free(0x4000, PAGE_SIZE));
    linux.vfs.close(fd).unwrap();
    assert_eq!(linux.vfs.open_at(-100, b"/other", 2, 0).unwrap(), fd);
    drop(exclusive);
    assert!(plan.try_admit(memory.memory_report()));
    let writer = layout.write();
    assert!(
        !writer.ready(),
        "admitted page preparation owns its backing"
    );
    assert_eq!(linux.apply_mmap(plan, &mut memory), Ok(0x4000));
    assert!(writer.ready());
    assert!(
        memory.parallel_view(&mut Default::default()).is_none(),
        "a writer accepted after mmap admission excludes CPU publication"
    );
    drop(writer);
    let view = memory.parallel_view(&mut Default::default()).unwrap();
    assert_eq!(view.read_array::<14>(0x4000).unwrap(), *b"original bytes");
    assert_eq!(linux.vfs.pread(fd, 32, 0).unwrap(), b"replacement");
}
#[test]
fn mapped_file_layout_keeps_the_original_call_through_driver_replacement_and_fd_reuse() {
    for replace in [false, true] {
        let mut v = trames_vfs::Vfs::default();
        v.import_file(b"/original", vec![0xa5; PAGE_SIZE as usize])
            .unwrap();
        v.import_file(b"/other", b"untouched".to_vec()).unwrap();
        let fd = v.open_at(-100, b"/original", 2, 0).unwrap();
        let mut memory = Memory::default();
        memory
            .map_backed(
                0x1000,
                v.mapping_pages(fd, 0, PAGE_SIZE, true, true).unwrap(),
                true,
                Permissions::RW,
                false,
            )
            .unwrap();
        let mut registry = trames_memory::parallel::Registry::default();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.write_array(0x1000, [0x42]).unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let disk: Arc<dyn FileExecutor> = Arc::new(Queue(send));
        let layouts = crate::FileLayouts::new(disk.clone());
        let target = t();
        let owner_signal = IoSignal::new(0, Arc::downgrade(&target));
        layouts.bind_owner(owner_signal.clone());
        let first_signal = IoSignal::new(0, Arc::downgrade(&target));
        let first = layouts.bind_reader(first_signal.clone());
        let mut epoch = trames_vfs::FileEpoch::default();
        let direct = DirectSyscalls::default()
            .with_files(epoch.capture(&v, true))
            .with_membership(v.shared_files())
            .with_paths(v.path_queries())
            .with_file_executor(disk)
            .with_file_layouts(layouts.clone());
        let args = [fd as u64, 1, 0, 0, 0, 0];
        let Some(IoAttempt::Blocked(wait)) =
            direct.start_file_call(46, args, &mut view, 1, &Arc::downgrade(&target))
        else {
            panic!("file layout must park directly, with no owner checkpoint");
        };
        let pending = wait.file_pending().unwrap();
        drop(wait);
        let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
        result.complete(work.run());
        let IoAttempt::Blocked(wait) =
            direct.start_retained_file(pending, 46, args, &mut view, 1, &Arc::downgrade(&target))
        else {
            panic!("accepted layout parks on original backing");
        };
        let pending = wait.file_pending().unwrap();
        drop((wait, direct));
        assert!(layouts.pending());
        let request = first.take_ready().pop().unwrap();
        let layout = request.layout().clone();
        let request = layouts.try_submit(request).err().unwrap();
        // Publish a resource wake before parking: it must survive the transfer.
        request.signal.notify();
        layouts.restore(request);
        let request = first.take_ready().pop().unwrap();
        layouts.restore(request);
        assert!(
            first.take_ready().is_empty(),
            "no polling while Views remain"
        );
        v.close(fd).unwrap();
        assert_eq!(v.open_at(-100, b"/other", 2, 0).unwrap(), fd);
        let replacement_signal = IoSignal::new(0, Arc::downgrade(&target));
        let replacement = replace.then(|| layouts.bind_reader(replacement_signal.clone()));
        drop(first);
        drop(view);
        memory.commit_parallel().unwrap();
        let request = if let Some(replacement) = &replacement {
            assert!(replacement_signal.ready());
            assert!(
                !owner_signal.ready(),
                "replaced source remains the only reader"
            );
            assert!(layouts.take_owner().is_empty());
            replacement.take_ready().pop().unwrap()
        } else {
            assert!(owner_signal.ready());
            layouts.take_owner().pop().unwrap()
        };
        assert!(layouts.try_submit(request).is_ok());
        assert!(!layouts.pending());
        let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            layout.pending(),
            "native executor still owns publication exclusion"
        );
        assert!(memory.parallel_view(&mut registry).is_none());
        result.complete(work.run());
        assert!(!layout.pending());
        let direct = DirectSyscalls::default();
        assert!(matches!(
            direct.start_retained_file(pending, 46, args, &mut memory, 1, &Arc::downgrade(&target)),
            IoAttempt::Complete(Ok(0))
        ));
        let original = v.open_at(-100, b"/original", 0, 0).unwrap();
        assert_eq!(v.read(original, 32).unwrap(), [0x42]);
        assert_eq!(v.pread(fd, 32, 0).unwrap(), b"untouched");
        assert!(
            receive.try_recv().is_err(),
            "accepted mutation executes exactly once"
        );
        epoch.finish();
    }
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
    assert!(
        wait.notification_external(),
        "disk completion must wake joined execution"
    );
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
#[test]
fn namespace_call_retains_original_path_and_dirfd_across_native_wait_and_reuse() {
    let (path, mut v) = disk();
    v.mkdir_at(-100, b"/old", 0o755).unwrap();
    v.mkdir_at(-100, b"/other", 0o755).unwrap();
    let fd = v.open_at(-100, b"/old", 0, 0).unwrap();
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.write(0x10000, b"child\0").unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let direct = DirectSyscalls::default()
        .with_paths(v.path_queries())
        .with_file_executor(Arc::new(Queue(send)));
    let target = t();
    let args = [fd as u64, 0x10000, 0o700, 0, 0, 0];
    let Some(IoAttempt::Blocked(wait)) =
        direct.start_file_call(34, args, &mut memory, 1, &Arc::downgrade(&target))
    else {
        panic!("persistent namespace work must release the execution slot")
    };
    let pending = wait.file_pending().unwrap();
    drop((wait, direct));
    memory.write(0x10000, b"other\0").unwrap();
    v.close(fd).unwrap();
    assert_eq!(v.open_at(-100, b"/other", 0, 0).unwrap(), fd);
    let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    std::thread::spawn(move || result.complete(work.run()))
        .join()
        .unwrap();
    assert!(matches!(
        DirectSyscalls::default().start_retained_file(
            pending,
            34,
            args,
            &mut memory,
            1,
            &Arc::downgrade(&target)
        ),
        IoAttempt::Complete(Ok(0))
    ));
    assert!(v.stat_at(-100, b"/old/child").is_ok());
    assert_eq!(v.stat_at(-100, b"/other/other"), Err(Errno(2)));
    drop(v);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn stream_wait_rearms_original_fds_and_copies_offsets_only_on_commit() {
    let mut v = trames_vfs::Vfs::default();
    v.import_file(b"/input", b"payload".to_vec()).unwrap();
    let source = v.open_at(-100, b"/input", 0, 0).unwrap();
    let [read, write] = v.pipe(0).unwrap();
    v.write(write, &vec![1; 65536]).unwrap();
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.write_array(0x10000, 1u64.to_le_bytes()).unwrap();
    let direct = DirectSyscalls::default()
        .with_membership(v.shared_files())
        .with_paths(v.path_queries());
    let target = t();
    let args = [write as u64, source as u64, 0x10000, 3, 0, 0];
    let Some(IoAttempt::Blocked(wait)) =
        direct.start_file_call(71, args, &mut memory, 1, &Arc::downgrade(&target))
    else {
        panic!("full destination")
    };
    let pending = wait.file_pending().unwrap();
    assert!(pending.interruptible());
    assert_eq!(memory.read_u64(0x10000).unwrap(), 1);
    v.close(source).unwrap();
    v.import_file(b"/other", b"wrong".to_vec()).unwrap();
    assert_eq!(v.open_at(-100, b"/other", 0, 0).unwrap(), source);
    drop((wait, direct));
    v.read(read, 65536).unwrap();
    let direct = DirectSyscalls::default();
    assert!(matches!(
        direct.start_retained_file(pending, 71, args, &mut memory, 1, &Arc::downgrade(&target)),
        IoAttempt::Complete(Ok(3))
    ));
    assert_eq!(memory.read_u64(0x10000).unwrap(), 4);
    assert_eq!(v.read(read, 3).unwrap(), b"ayl");
}

#[derive(Default)]
struct FileSignal(std::sync::atomic::AtomicUsize);
impl trames_vfs::TaskSignal for FileSignal {
    fn raise(&self, signal: u32) {
        assert_eq!(signal, 25);
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
#[test]
fn size_failure_notifies_the_source_without_inline_or_native_owner_checkpoint() {
    for native in [false, true] {
        let (directory, mut v) = if native {
            let (p, v) = disk();
            (Some(p), v)
        } else {
            (None, trames_vfs::Vfs::default())
        };
        v.import_file(b"/limited", Vec::new()).unwrap();
        let fd = v.open_at(-100, b"/limited", 2, 0).unwrap();
        v.set_file_size_limit(0);
        let mut epoch = trames_vfs::FileEpoch::default();
        let files = epoch.capture(&v, true);
        let signal = Arc::new(FileSignal::default());
        let (send, receive) = std::sync::mpsc::channel();
        let direct = DirectSyscalls::default()
            .with_files(files)
            .with_membership(v.shared_files())
            .with_paths(v.path_queries())
            .with_task_signal(signal.clone())
            .with_file_executor(Arc::new(Queue(send)));
        let mut m = Memory::default();
        m.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x10000, b"x").unwrap();
        let args = [fd as u64, 0x10000, 1, 0, 0, 0];
        let wake = t();
        let result = direct
            .start_file_call(64, args, &mut m, 1, &Arc::downgrade(&wake))
            .unwrap();
        let result = if native {
            let IoAttempt::Blocked(wait) = result else {
                panic!("native operation should park only its source")
            };
            let pending = wait.file_pending().unwrap();
            drop(wait);
            let (work, completion) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
            completion.complete(work.run());
            direct.start_retained_file(pending, 64, args, &mut m, 1, &Arc::downgrade(&wake))
        } else {
            result
        };
        assert!(matches!(result, IoAttempt::Complete(Err(Errno(27)))));
        assert_eq!(signal.0.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(v.pread(fd, 8, 0).unwrap(), b"");
        drop((direct, v));
        epoch.finish();
        if let Some(p) = directory {
            std::fs::remove_dir_all(p).unwrap();
        }
    }
}
