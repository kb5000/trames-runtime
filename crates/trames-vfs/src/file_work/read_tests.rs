// SPDX-License-Identifier: GPL-3.0-or-later
//! Actual multi-page reads retain bytes through IO waits and guest copyout.
use super::*;

struct Store(std::path::PathBuf);
impl Store {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "trames-read-work-{}-{}",
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
fn write(v: &mut Vfs, path: &[u8], bytes: &[u8]) {
    let fd = v.open_at(AT_FDCWD, path, 2, 0).unwrap();
    assert_eq!(v.write(fd, bytes).unwrap(), bytes.len());
    v.close(fd).unwrap();
}
fn text(v: &mut Vfs, path: &[u8]) -> Vec<u8> {
    let fd = v.open_at(AT_FDCWD, path, 0, 0).unwrap();
    let data = v.pread(fd, 4096, 0).unwrap();
    v.close(fd).unwrap();
    data
}
fn stat(v: &mut Vfs, field: &str) -> u64 {
    String::from_utf8(text(v, b"/sys/fs/cgroup/a/io.stat"))
        .unwrap()
        .split_whitespace()
        .find_map(|word| word.strip_prefix(field).map(|value| value.parse().unwrap()))
        .unwrap_or(0)
}
fn setup(store: &Store) -> (Vfs, Vec<u8>, u32, FileTarget) {
    let mut v = Vfs::open_disk(&store.0, Default::default()).unwrap();
    v.set_runtime_info(1, Default::default());
    let bytes = [vec![1; 4096], vec![2; 4096], vec![3; 4096]].concat();
    v.import_file(b"/data", bytes.clone()).unwrap();
    write(
        &mut v,
        b"/sys/fs/cgroup/cgroup.subtree_control",
        b"+memory +io",
    );
    v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/a", 0o755).unwrap();
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=1");
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    let fd = v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
    let target = v
        .shared_files()
        .lookup(fd)
        .unwrap()
        .unwrap()
        .file_target()
        .unwrap();
    (v, bytes, fd, target)
}
fn waiting(outcome: FileOutcome) -> FileWork {
    match outcome {
        FileOutcome::Waiting(work) => work,
        _ => panic!("expected resource wait"),
    }
}
fn complete(outcome: FileOutcome) -> FileReply {
    match outcome {
        FileOutcome::Complete(reply) => reply,
        _ => panic!("expected original read completion"),
    }
}
fn watch(v: &mut Vfs) -> u32 {
    let fd = v.inotify_init(O_NONBLOCK).unwrap();
    v.inotify_add(fd, b"/data", inotify::ACCESS).unwrap();
    fd
}
fn one_access(v: &mut Vfs, fd: u32) {
    let event = v.read(fd, 4096).unwrap();
    assert_eq!(event.len(), 16);
    assert_eq!(
        u32::from_le_bytes(event[4..8].try_into().unwrap()),
        inotify::ACCESS
    );
    assert_eq!(v.read(fd, 4096), Err(Errno(11)));
}
#[test]
fn a_ready_resource_receipt_keeps_its_owner_without_masking_a_new_position_wait() {
    struct Wake;
    impl trames_shared::IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    let mut v = Vfs::default();
    v.import_file(b"/data", b"data".to_vec()).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
    let target = v
        .shared_files()
        .lookup(fd)
        .unwrap()
        .unwrap()
        .file_target()
        .unwrap();
    let position = crate::read_reply::FileRead::begin(target.0.clone()).unwrap();
    let ready = Arc::new(trames_memory::PageWait::default());
    ready.finish();
    let owner = Arc::new(());
    let retained = Arc::downgrade(&owner);
    let mut work = FileWork::new(
        &v.path_queries(),
        target,
        FileCommand::Read {
            count: 4,
            offset: None,
        },
    );
    work.resource_wait = Some(resource_io::holding(ready, owner));
    assert!(work.waiting());
    assert!(!work.ready());
    let wake: Arc<dyn trames_shared::IoWake> = Arc::new(Wake);
    let signal = IoSignal::new(1, Arc::downgrade(&wake));
    let sources = work.wait_sources(&signal).unwrap();
    assert!(
        !signal.ready(),
        "a retired ready source must not poll the new wait"
    );
    let work = waiting(work.run());
    assert!(retained.upgrade().is_some());
    drop(position);
    assert!(signal.ready());
    assert!(work.ready());
    let reply = complete(work.run());
    assert!(reply.result.is_ok());
    assert!(retained.upgrade().is_none());
    drop(sources);
}
#[test]
fn query_splice_keeps_its_outer_transfer_while_a_regular_child_waits_for_io() {
    for cancel in [false, true] {
        let store = Store::new();
        let (mut v, original, fd, target) = setup(&store);
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/b", 0o755).unwrap();
        let [reader, writer] = v.pipe(0).unwrap();
        let output = v.shared_files().lookup(writer).unwrap().unwrap();
        let paths = v.path_queries();
        let task = v.cgroup_task(1).unwrap();
        let resources = task.resource_scope();
        assert!(paths
            .uring_query(|view| view.splice(fd, writer, 12288, None, None))
            .is_none());
        let work = paths
            .take_open_work()
            .expect("the query retains the whole splice");
        let pending = waiting(work.exclusive().run());
        assert!(pending.layout_exclusive.is_none());
        assert_eq!(stat(&mut v, "rios="), 1);
        assert_eq!(v.read(reader, 1), Err(Errno(11)));
        assert_eq!(target.0.open.file_position.snapshot(), 0);
        write(&mut v, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
        drop(resources);
        let _other = task.resource_scope();
        v.close(fd).unwrap();
        v.rename_at(AT_FDCWD, b"/data", AT_FDCWD, b"/original", 0)
            .unwrap();
        v.import_file(b"/data", b"replacement".to_vec()).unwrap();
        assert_eq!(v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap(), fd);
        let other_memory = text(&mut v, b"/sys/fs/cgroup/b/memory.current");
        if cancel {
            drop(pending);
            assert_eq!(target.0.open.file_position.snapshot(), 0);
            assert_eq!(
                output
                    .open
                    .pipe
                    .as_ref()
                    .unwrap()
                    .data
                    .lock()
                    .unwrap()
                    .write_reserved,
                0
            );
            assert_eq!(v.read(reader, 1), Err(Errno(11)));
            assert_eq!(stat(&mut v, "rios="), 1);
        } else {
            write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=max");
            let reply = complete(pending.exclusive().run());
            assert!(matches!(
                reply.result,
                Ok(FileValue::Transfer { count: 12288, .. })
            ));
            drop(reply.resources);
            assert_eq!(v.read(reader, 12288).unwrap(), original);
            assert_eq!(target.0.open.file_position.snapshot(), 12288);
            assert_eq!(v.seek(fd, 0, 1), Ok(0));
            assert_eq!(stat(&mut v, "rios="), 3);
            assert_eq!(stat(&mut v, "rbytes="), 12288);
        }
        assert_eq!(
            text(&mut v, b"/sys/fs/cgroup/b/memory.current"),
            other_memory
        );
    }
}
#[test]
fn all_read_entries_keep_prefix_owner_position_and_original_inode_until_copyout() {
    for mode in 0..3 {
        for explicit in [false, true] {
            let store = Store::new();
            let (mut v, original, fd, target) = setup(&store);
            let notify = watch(&mut v);
            v.seek(fd, 7, 0).unwrap();
            let task = v.cgroup_task(1).unwrap();
            let resources = task.resource_scope();
            let command = FileCommand::Read {
                count: 12288,
                offset: explicit.then_some(7),
            };
            let layout = target.layout().unwrap();
            let outcome = match mode {
                0 => {
                    let admission = layout.write().try_enter().ok().unwrap();
                    FileWork::new(&v.path_queries(), target.clone(), command)
                        .queued()
                        .enter_layout(admission)
                        .run()
                }
                1 => FileWork::run_owned(&mut v, target.clone(), command),
                _ => FileWork::run_inline(&v.path_queries(), target.clone(), command),
            };
            let pending = waiting(outcome);
            assert_eq!(pending.read.as_ref().unwrap().bytes, original[7..4096]);
            assert_eq!(target.0.open.file_position.snapshot(), 7);
            assert_eq!(
                v.read(notify, 4096),
                Err(Errno(11)),
                "no ACCESS for an unfinished prefix"
            );
            assert!(pending.layout_exclusive.is_none());
            let other_reader = layout
                .try_read(trames_memory::Memory::default().memory_report())
                .unwrap();
            drop(other_reader);
            assert_eq!(stat(&mut v, "rios="), 1);
            // Read custody is not a data transaction. Another OFD can change
            // bytes while the original caller is waiting for a later page.
            write(&mut v, b"/sys/fs/cgroup/cgroup.procs", b"1");
            drop(resources);
            let writer = v.open_at(AT_FDCWD, b"/data", 2, 0).unwrap();
            assert_eq!(v.pwrite(writer, &[99], 7), Ok(1));
            assert_eq!(v.pwrite(writer, &[77], 4096), Ok(1));
            v.close(writer).unwrap();
            v.close(fd).unwrap();
            v.rename_at(AT_FDCWD, b"/data", AT_FDCWD, b"/accepted", 0)
                .unwrap();
            v.import_file(b"/data", b"other inode".to_vec()).unwrap();
            assert_eq!(v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap(), fd);
            write(&mut v, b"/sys/fs/cgroup/a/memory.reclaim", b"4096");
            assert_eq!(text(&mut v, b"/sys/fs/cgroup/a/memory.current"), b"0\n");
            write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=max");
            assert!(pending.ready());
            assert!(
                pending.host_work(),
                "the read must not wait on its own OFD position"
            );
            let reply = std::thread::spawn(move || complete(pending.run()))
                .join()
                .unwrap();
            let mut expected = original[7..].to_vec();
            expected[4096 - 7] = 77;
            match reply.result.unwrap() {
                FileValue::Read(reply) if !explicit => {
                    let (bytes, mut position) = reply.into_parts();
                    assert_eq!(bytes, expected);
                    assert_eq!(target.0.open.file_position.snapshot(), 7);
                    position.record(13); // A later output fault exposes only this prefix.
                    drop(position);
                    assert_eq!(target.0.open.file_position.snapshot(), 20);
                }
                FileValue::Bytes(bytes) if explicit => {
                    assert_eq!(bytes, expected);
                    assert_eq!(target.0.open.file_position.snapshot(), 7);
                }
                _ => panic!("the accepted read keeps its original position mode"),
            }
            assert_eq!(v.seek(fd, 0, 1).unwrap(), 0, "the reused FD is independent");
            assert_eq!(
                stat(&mut v, "rios="),
                3,
                "the reclaimed prefix is not read twice"
            );
            assert_eq!(stat(&mut v, "rbytes="), 12288);
            one_access(&mut v, notify);
        }
    }
}
#[test]
fn a_caught_signal_delivers_only_the_retained_read_prefix_and_releases_its_wait() {
    for prefix in [false, true] {
        let store = Store::new();
        let (mut v, original, fd, target) = setup(&store);
        if !prefix {
            write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 rbps=1");
        }
        let notify = watch(&mut v);
        v.seek(fd, 7, 0).unwrap();
        let task = v.cgroup_task(1).unwrap();
        let resources = task.resource_scope();
        let pending = waiting(
            FileWork::from_vfs(
                &v,
                target.clone(),
                FileCommand::Read {
                    count: 12288,
                    offset: None,
                },
            )
            .run(),
        );
        assert!(pending.interruptible_wait());
        let retired = Arc::downgrade(pending.resource_wait.as_ref().unwrap());
        let reply = pending.interrupted();
        assert!(retired.upgrade().is_none());
        if prefix {
            let FileValue::Read(reply) = reply.result.unwrap() else {
                panic!("retained read position");
            };
            let (bytes, mut position) = reply.into_parts();
            assert_eq!(bytes, original[7..4096]);
            position.record(3);
            drop(position);
            assert_eq!(target.0.open.file_position.snapshot(), 10);
            one_access(&mut v, notify);
        } else {
            assert!(matches!(reply.result, Err(Errno(4))));
            assert_eq!(target.0.open.file_position.snapshot(), 7);
            assert_eq!(v.read(notify, 4096), Err(Errno(11)));
        }
        assert_eq!(stat(&mut v, "rios="), u64::from(prefix));
        drop(resources);
        assert_eq!(v.seek(fd, 0, 1).unwrap(), if prefix { 10 } else { 7 });
    }
}
#[test]
fn dropping_a_read_releases_position_without_publishing_unconsumed_bytes() {
    let store = Store::new();
    let (mut v, _, fd, target) = setup(&store);
    let notify = watch(&mut v);
    let task = v.cgroup_task(1).unwrap();
    let resources = task.resource_scope();
    let pending = waiting(
        FileWork::from_vfs(
            &v,
            target,
            FileCommand::Read {
                count: 12288,
                offset: None,
            },
        )
        .run(),
    );
    drop(pending);
    assert_eq!(v.seek(fd, 0, 1).unwrap(), 0);
    assert_eq!(v.read(notify, 4096), Err(Errno(11)));
    drop(resources);
    write(&mut v, b"/sys/fs/cgroup/a/memory.reclaim", b"4096");
    assert_eq!(text(&mut v, b"/sys/fs/cgroup/a/memory.current"), b"0\n");
}
#[test]
fn native_unlink_keeps_the_original_open_backend_and_read_prefix() {
    let store = Store::new();
    let (mut v, original, fd, target) = setup(&store);
    let notify = watch(&mut v);
    let backing = match &target.0.open.node.as_ref().unwrap().borrow().content {
        Content::File(data) => data.disk_source().unwrap().0.path.clone(),
        _ => unreachable!(),
    };
    let task = v.cgroup_task(1).unwrap();
    let resources = task.resource_scope();
    let pending = waiting(
        FileWork::from_vfs(
            &v,
            target,
            FileCommand::Read {
                count: 12288,
                offset: None,
            },
        )
        .run(),
    );
    std::fs::remove_file(backing).unwrap(); // The accepted native FD retains its bytes.
    drop(resources);
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=max");
    let bytes = complete(pending.run())
        .result
        .unwrap()
        .into_bytes()
        .unwrap();
    assert_eq!(bytes, original);
    assert_eq!(v.seek(fd, 0, 1).unwrap(), 12288);
    assert_eq!(stat(&mut v, "rios="), 3);
    one_access(&mut v, notify);
}
#[test]
fn mapped_overlay_bytes_are_saved_before_a_later_underlying_page_waits() {
    let store = Store::new();
    let (mut v, mut original, fd, target) = setup(&store);
    let writer = v.open_at(AT_FDCWD, b"/data", 2, 0).unwrap();
    let maps = v.mapping_pages(writer, 0, 12288, true, true).unwrap();
    maps[0].write(7, &[99]).unwrap();
    original[7] = 99;
    let task = v.cgroup_task(1).unwrap();
    let resources = task.resource_scope();
    let pending = waiting(
        FileWork::from_vfs(
            &v,
            target,
            FileCommand::Read {
                count: 12288,
                offset: Some(7),
            },
        )
        .run(),
    );
    assert_eq!(pending.read.as_ref().unwrap().bytes[0], 99);
    assert_eq!(pending.read.as_ref().unwrap().bytes.len(), 8192 - 7);
    drop(resources);
    maps[0].write(7, &[88]).unwrap();
    maps[2].write(0, &[77]).unwrap();
    original[8192] = 77;
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=max");
    let bytes = complete(pending.run())
        .result
        .unwrap()
        .into_bytes()
        .unwrap();
    assert_eq!(bytes, original[7..]);
    assert_eq!(v.seek(fd, 0, 1).unwrap(), 0);
}
#[test]
fn fast_cross_page_reads_fall_back_before_cold_io_and_warm_reads_issue_no_backend_request() {
    let store = Store::new();
    let (mut v, original, fd, target) = setup(&store);
    write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"-memory");
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=max");
    let task = v.cgroup_task(1).unwrap();
    let resources = task.resource_scope();
    let direct = FileEpoch::default().capture(&v, true).get(fd).unwrap();
    assert!(direct
        .read_reply(12288, None, &mut DiskReadCache::default())
        .is_none());
    assert_eq!(stat(&mut v, "rios="), 0);
    assert_eq!(target.0.open.file_position.snapshot(), 0);
    assert_eq!(
        direct
            .read_reply(4096, Some(0), &mut DiskReadCache::default())
            .unwrap()
            .unwrap()
            .into_bytes()
            .unwrap(),
        original[..4096]
    );
    assert_eq!(stat(&mut v, "rios="), 1);
    assert!(direct
        .read_reply(12288, None, &mut DiskReadCache::default())
        .is_none());
    assert_eq!(
        stat(&mut v, "rios="),
        1,
        "cached-prefix probing issues no cold tail IO"
    );
    let bytes = complete(
        FileWork::from_vfs(
            &v,
            target.clone(),
            FileCommand::Read {
                count: 12288,
                offset: Some(0),
            },
        )
        .run(),
    )
    .result
    .unwrap()
    .into_bytes()
    .unwrap();
    assert_eq!(bytes, original);
    assert_eq!(stat(&mut v, "rios="), 3);
    // Only existing cached bytes remain in the fast path, including unaligned
    // page boundaries, and no new controller charge can occur in that probe.
    assert_eq!(
        direct
            .read_reply(8192, Some(7), &mut DiskReadCache::default())
            .unwrap()
            .unwrap()
            .into_bytes()
            .unwrap(),
        original[7..8199]
    );
    assert_eq!(stat(&mut v, "rios="), 3);
    drop(resources);
}
