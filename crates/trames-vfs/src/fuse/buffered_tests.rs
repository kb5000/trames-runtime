// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::fuse::tests::{entry, id, mount_vfs_negotiated};

fn setup(flags: u32, size: u64) -> (Vfs, Arc<Device>, SharedFd, Arc<File>, Arc<Executor>) {
    setup_limit(flags, size, 128 * 1024)
}
fn setup_limit(
    flags: u32,
    size: u64,
    limit: u32,
) -> (Vfs, Arc<Device>, SharedFd, Arc<File>, Arc<Executor>) {
    let (v, dev) = mount_vfs_negotiated(Vfs::default(), limit, "", 1 << 16);
    let (_, fd) = open_file(&v, dev.connection().unwrap(), flags);
    let original = v.shared_files().lookup(fd).unwrap().unwrap();
    let Some(events::SharedControl::FuseFile(file)) = &original.open.control else {
        panic!()
    };
    let file = file.clone();
    file.attr.lock().unwrap()[8..16].copy_from_slice(&size.to_le_bytes());
    file.reference
        .fs
        .xattr_unsupported
        .store(2, Ordering::Relaxed);
    (v, dev, original, file, Executor::new())
}
fn actor(v: &Vfs, executor: &Arc<Executor>) -> FileActorScope {
    FileActorScope::enter_with_sync(
        Arc::new(CredentialState::new(v.credentials.clone())),
        v.pid,
        Some(executor.clone()),
    )
}
fn write(
    v: &Vfs,
    file: &Arc<File>,
    original: &SharedFd,
    at: Option<u64>,
    bytes: &[u8],
) -> Metadata {
    file.operation(
        v,
        &FileCommand::Write {
            offset: at,
            bytes: bytes.to_vec(),
        },
        original,
    )
    .unwrap()
    .unwrap()
}
fn count(operation: &mut Metadata, v: &mut Vfs, expected: u64) {
    assert!(matches!(operation.take(v), Some(Ok(FileValue::Count(n))) if n == expected));
}
fn times(c: &Connection, executor: &Executor) {
    let mut request = None;
    for _ in 0..16 {
        match c.read(8192) {
            Ok(bytes) => {
                request = Some(bytes);
                break;
            }
            Err(Errno(11)) => executor.step(),
            other => panic!("timestamp request: {other:?}"),
        }
    }
    let request = request.expect("bounded timestamp continuation");
    assert_eq!(u32::from_le_bytes(request[4..8].try_into().unwrap()), 4);
    assert_eq!(
        u32::from_le_bytes(request[40..44].try_into().unwrap()),
        32 | 64 | 1024
    );
    assert_eq!(&request[48..56], &9876u64.to_le_bytes());
    let mut attr = [0; 104];
    attr[16..].copy_from_slice(&entry(10, 210, 0o100600)[40..]);
    answer(c, &request, &attr);
    executor.resume();
}

fn force_background(file: &Arc<File>) {
    writeback::background(&file.attr.cache.writer().expect("original writable OFD"));
}

#[test]
fn write_only_partial_page_reads_original_bytes_and_completes_before_daemon_write() {
    let (mut v, dev, original, file, executor) = setup(1, PAGE_SIZE);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let mut operation = write(&v, &file, &original, Some(31), b"new");
    assert!(operation.take(&mut v).is_none());
    let read = receive(c, 15, 10);
    assert_eq!(&read[40..48], &9876u64.to_le_bytes());
    assert_eq!(u32::from_le_bytes(read[72..76].try_into().unwrap()) & 3, 1);
    answer(c, &read, &vec![b'o'; PAGE_SIZE as usize]);
    count(&mut operation, &mut v, 3);
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "write returned before writeback submission"
    );
    assert_eq!(file.attr.cache.cached(29, 7).unwrap(), b"oonewoo");
    drop(operation);
    force_background(&file);
    executor.step();
    let request = receive(c, 16, 10);
    assert_eq!(&request[60..64], &1u32.to_le_bytes());
    assert_eq!(&request[80 + 29..80 + 36], b"oonewoo");
    ack(c, &request);
    executor.resume();
    times(c, &executor);
    assert!(!file.attr.cache.dirty());
    assert_eq!(file.attr.dirty_times.load(Ordering::Relaxed), 0);
}

#[test]
fn full_pages_skip_read_and_sparse_cached_reads_zero_holes_without_shrinking_inode() {
    let (mut v, dev, original, file, executor) = setup(2, 0);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let mut operation = write(&v, &file, &original, Some(2 * PAGE_SIZE), b"tail");
    count(&mut operation, &mut v, 4);
    drop(operation);
    assert_eq!(c.read(8192), Err(Errno(11)));
    let mut read = file
        .operation(
            &v,
            &FileCommand::Read {
                offset: Some(0),
                count: 3 * PAGE_SIZE as usize,
            },
            &original,
        )
        .unwrap()
        .unwrap();
    assert!(read.take(&mut v).is_none());
    let request = receive(c, 15, 10);
    assert_eq!(&request[48..56], &0u64.to_le_bytes());
    assert_eq!(&request[56..60], &(2 * PAGE_SIZE as u32).to_le_bytes());
    answer(c, &request, &[]);
    let Some(Ok(FileValue::Bytes(bytes))) = read.take(&mut v) else {
        panic!("buffered sparse read")
    };
    assert_eq!(bytes.len(), 2 * PAGE_SIZE as usize + 4);
    assert!(bytes[..2 * PAGE_SIZE as usize].iter().all(|b| *b == 0));
    assert_eq!(&bytes[2 * PAGE_SIZE as usize..], b"tail");
    assert_eq!(
        u64::from_le_bytes(file.attr.lock().unwrap()[8..16].try_into().unwrap()),
        2 * PAGE_SIZE + 4
    );
    executor.close();
}

#[test]
fn synchronous_buffered_write_keeps_position_until_data_times_and_fsync_complete() {
    let (mut v, dev, original, file, executor) = setup(2, 0);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let mut operation = file
        .operation(
            &v,
            &FileCommand::WriteSync {
                offset: None,
                bytes: b"sync".to_vec(),
                data_only: false,
            },
            &original,
        )
        .unwrap()
        .unwrap();
    assert!(operation.take(&mut v).is_none());
    assert_eq!(original.open.file_position.snapshot(), 0);
    executor.step();
    let request = receive(c, 16, 10);
    ack(c, &request);
    executor.resume();
    times(c, &executor);
    assert!(operation.take(&mut v).is_none());
    let request = receive(c, 20, 10);
    assert_eq!(original.open.file_position.snapshot(), 0);
    answer(c, &request, &[]);
    count(&mut operation, &mut v, 4);
    assert_eq!(original.open.file_position.snapshot(), 4);
}

#[test]
fn later_getattr_and_mode_change_keep_local_size_and_mtime_authority() {
    let (mut v, dev, original, file, executor) = setup(2, 0);
    let _actor = actor(&v, &executor);
    let mut operation = write(&v, &file, &original, Some(0), b"cached");
    count(&mut operation, &mut v, 6);
    drop(operation);
    let before = file.attr.lock().unwrap().to_vec();
    let mut stale: [u8; 88] = entry(10, 210, 0o100600)[40..].try_into().unwrap();
    file.attr
        .refresh(
            &file.reference.fs,
            &mut stale,
            file.reference.fs.connection.current_attr_version(),
            (60, 0),
            inode::Update::Read,
        )
        .unwrap();
    assert_eq!(&stale[8..16], &6u64.to_le_bytes());
    assert_eq!(&stale[32..48], &before[32..48]);
    stale[8..16].fill(0);
    stale[32..48].fill(0);
    assert!(!file
        .attr
        .refresh(
            &file.reference.fs,
            &mut stale,
            1,
            (60, 0),
            inode::Update::Read
        )
        .unwrap());
    assert_eq!(&stale[8..16], &6u64.to_le_bytes());
    assert_eq!(&stale[32..48], &before[32..48]);
    let c = dev.connection().unwrap();
    let mut stat = file.stat(&v).unwrap();
    let request = receive(c, 3, 10);
    let mut payload = [0; 104];
    payload[16..].copy_from_slice(&entry(10, 210, 0o100600)[40..]);
    answer(c, &request, &payload);
    let Some(Ok(FileValue::FuseStat(bytes, _))) = stat.take(&mut v) else {
        panic!()
    };
    assert_eq!(&bytes[48..56], &6u64.to_le_bytes());
    executor.close();
}

#[test]
fn close_without_flush_support_still_drains_cached_data_and_timestamps() {
    let (mut v, dev, original, file, executor) = setup(2, 0);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    file.disable_flush();
    let mut operation = write(&v, &file, &original, Some(0), b"close");
    count(&mut operation, &mut v, 5);
    drop(operation);
    let mut close = file
        .flush(&v)
        .unwrap()
        .expect("dirty close cannot be omitted");
    assert!(close.take(&mut v).is_none());
    executor.step();
    let request = receive(c, 16, 10);
    ack(c, &request);
    executor.resume();
    times(c, &executor);
    count(&mut close, &mut v, 0);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn failed_background_write_is_reported_once_to_the_original_ofd_sync() {
    let (mut v, dev, original, file, executor) = setup(2, 0);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let mut operation = write(&v, &file, &original, Some(0), b"error");
    count(&mut operation, &mut v, 5);
    drop(operation);
    force_background(&file);
    executor.step();
    let request = receive(c, 16, 10);
    c.write(&reply(id(&request), -28, &[])).unwrap();
    executor.resume();
    times(c, &executor);
    assert!(matches!(
        file.sync(&v, false, 0, None, None),
        Err(Errno(28))
    ));
    let mut sync = file.sync(&v, false, 0, None, None).unwrap();
    let request = receive(c, 20, 10);
    answer(c, &request, &[]);
    count(&mut sync, &mut v, 0);
}

#[test]
fn direct_io_bypasses_cache_and_does_not_issue_partial_page_reads() {
    let (mut v, dev, original, file, executor) = setup(2 | O_DIRECT, PAGE_SIZE);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let mut operation = write(&v, &file, &original, Some(17), b"direct");
    assert!(operation.take(&mut v).is_none());
    let request = receive(c, 16, 10);
    assert_eq!(&request[60..64], &[0; 4]);
    assert_eq!(&request[80..], b"direct");
    ack(c, &request);
    count(&mut operation, &mut v, 6);
    assert!(!file.attr.cache.dirty());
    assert!(executor.jobs.lock().unwrap().is_empty());
}

#[test]
fn truncating_queued_buffered_pages_never_writes_past_the_new_eof() {
    let (mut v, dev, original, file, executor) = setup(2, 0);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let mut operation = write(
        &v,
        &file,
        &original,
        Some(0),
        &vec![b'z'; 2 * PAGE_SIZE as usize],
    );
    count(&mut operation, &mut v, 2 * PAGE_SIZE);
    drop(operation);
    force_background(&file);
    let mut truncate = Metadata::file_size(&v, file.clone(), 3, false).unwrap();
    let request = receive(c, 3, 10);
    let mut attr = [0; 104];
    attr[16..].copy_from_slice(&entry(10, 210, 0o100600)[40..]);
    answer(c, &request, &attr);
    assert!(truncate.take(&mut v).is_none());
    let request = receive(c, 4, 10);
    attr[24..32].copy_from_slice(&3u64.to_le_bytes());
    answer(c, &request, &attr);
    count(&mut truncate, &mut v, 0);
    drop(truncate);
    executor.step();
    let request = receive(c, 16, 10);
    assert_eq!(&request[80..], b"zzz");
    ack(c, &request);
    executor.resume();
    times(c, &executor);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn cancelling_partial_write_keeps_original_read_lifetime_without_dirtying_or_replay() {
    let (mut v, dev, original, file, executor) = setup(2, PAGE_SIZE);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let mut operation = write(&v, &file, &original, None, b"cancel");
    assert!(operation.take(&mut v).is_none());
    let request = receive(c, 15, 10);
    drop(operation);
    assert!(!file.busy());
    assert!(!file.attr.cache.dirty());
    // A late completion belongs to the cancelled original read, never a new
    // write or reused descriptor. No data WRITE has been committed.
    answer(c, &request, &vec![b'x'; PAGE_SIZE as usize]);
    assert_eq!(original.open.file_position.snapshot(), 0);
    assert!(executor.jobs.lock().unwrap().is_empty());
}

#[test]
fn cached_read_on_layout_worker_uses_accepted_caller_without_thread_local_actor() {
    let (mut v, _dev, original, file, executor) = setup(2, 0);
    {
        let _actor = actor(&v, &executor);
        let mut operation = write(&v, &file, &original, Some(0), &vec![b'x'; 8192]);
        count(&mut operation, &mut v, 8192);
    }
    assert!(crate::file_actor::current().is_none());
    let mut read = file
        .operation(
            &v,
            &FileCommand::Read {
                offset: Some(0),
                count: 8192,
            },
            &original,
        )
        .unwrap()
        .unwrap();
    assert!(
        matches!(read.take(&mut v), Some(Ok(FileValue::Bytes(bytes))) if bytes == vec![b'x';8192])
    );
    executor.close();
}

#[test]
fn cold_read_retains_accepted_caller_and_length_across_worker_change_and_file_growth() {
    let (mut v, dev, original, file, _executor) = setup(2, 4);
    let c = dev.connection().unwrap();
    assert!(crate::file_actor::current().is_none());
    let mut read = file
        .operation(
            &v,
            &FileCommand::Read {
                offset: Some(0),
                count: 8,
            },
            &original,
        )
        .unwrap()
        .unwrap();
    assert!(read.take(&mut v).is_none());
    let request = receive(c, 15, 10);
    assert_eq!(
        &request[32..36],
        &file.reference.fs.caller(&v).pid.to_le_bytes()
    );
    file.attr.lock().unwrap()[8..16].copy_from_slice(&8u64.to_le_bytes());
    answer(c, &request, b"original");
    assert!(matches!(read.take(&mut v), Some(Ok(FileValue::Bytes(bytes))) if bytes == b"orig"));
}

fn wide_request(c: &Connection, opcode: u32) -> Vec<u8> {
    let request = c.read(256 * 1024).unwrap();
    assert_eq!(&request[4..8], &opcode.to_le_bytes());
    assert_eq!(&request[16..24], &10u64.to_le_bytes());
    request
}

#[test]
fn cold_read_batches_obey_wire_limit_and_publish_short_read_zeroes_per_original_page() {
    let (v, dev, original, file, executor) = setup(2, 40 * PAGE_SIZE);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let reads = file
        .attr
        .cache
        .read_pages_as(
            &file,
            &original,
            0,
            40 * PAGE_SIZE as usize,
            file.reference.fs.caller(&v),
        )
        .unwrap();
    let first = wide_request(c, 15);
    let second = wide_request(c, 15);
    assert_eq!(&first[56..60], &(32 * PAGE_SIZE as u32).to_le_bytes());
    assert_eq!(&second[48..56], &(32 * PAGE_SIZE).to_le_bytes());
    assert_eq!(&second[56..60], &(8 * PAGE_SIZE as u32).to_le_bytes());
    assert_eq!(c.read(8192), Err(Errno(11)));
    answer(c, &first, &vec![b'a'; 32 * PAGE_SIZE as usize]);
    assert!(reads[..32].iter().all(|read| read.result().is_some()));
    assert!(reads[32..].iter().all(|read| read.result().is_none()));
    answer(c, &second, &vec![b'b'; PAGE_SIZE as usize + 7]);
    let mut bytes = [0; PAGE_SIZE as usize];
    reads[33].copy_to(0, &mut bytes).unwrap();
    assert_eq!(&bytes[..7], &[b'b'; 7]);
    assert!(bytes[7..].iter().all(|byte| *byte == 0));
    reads[39].copy_to(0, &mut bytes).unwrap();
    assert!(bytes.iter().all(|byte| *byte == 0));
    assert_eq!(
        u64::from_le_bytes(file.attr.lock().unwrap()[8..16].try_into().unwrap()),
        40 * PAGE_SIZE
    );
}

#[test]
fn cancelling_batch_leader_keeps_one_original_request_for_a_remaining_page_follower() {
    let (v, dev, original, file, executor) = setup(2, 3 * PAGE_SIZE);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let reads = file
        .attr
        .cache
        .read_pages_as(
            &file,
            &original,
            0,
            3 * PAGE_SIZE as usize,
            file.reference.fs.caller(&v),
        )
        .unwrap();
    let request = wide_request(c, 15);
    let follower = file.read_page(&original, 1).unwrap();
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "joining an accepted page sends no extra READ"
    );
    drop(reads);
    let mut payload = vec![b'a'; 3 * PAGE_SIZE as usize];
    payload[PAGE_SIZE as usize..2 * PAGE_SIZE as usize].fill(b'b');
    answer(c, &request, &payload);
    let mut bytes = [0; 16];
    follower.copy_to(0, &mut bytes).unwrap();
    assert_eq!(&bytes, &[b'b'; 16]);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn retired_batch_pages_deliver_accepted_bytes_without_repopulating_notified_cache() {
    let (v, dev, original, file, executor) = setup(2, 2 * PAGE_SIZE);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let reads = file
        .attr
        .cache
        .read_pages_as(
            &file,
            &original,
            0,
            2 * PAGE_SIZE as usize,
            file.reference.fs.caller(&v),
        )
        .unwrap();
    let request = wide_request(c, 15);
    file.attr.cache.invalidate_all();
    let mut payload = vec![b'a'; 2 * PAGE_SIZE as usize];
    payload[PAGE_SIZE as usize..].fill(b'b');
    answer(c, &request, &payload);
    let mut bytes = [0; 4];
    reads[0].copy_to(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"aaaa");
    reads[1].copy_to(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"bbbb");
    assert!(file.attr.cache.cached(0, 2 * PAGE_SIZE as usize).is_none());
}

#[test]
fn batch_followers_keep_the_original_ofd_after_close_and_numeric_reuse() {
    let (mut v, dev, original, file, executor) = setup(2, 2 * PAGE_SIZE);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let reads = file
        .attr
        .cache
        .read_pages_as(
            &file,
            &original,
            0,
            2 * PAGE_SIZE as usize,
            file.reference.fs.caller(&v),
        )
        .unwrap();
    let request = wide_request(c, 15);
    let fd = (0..32)
        .find(|fd| {
            v.shared_files()
                .lookup(*fd)
                .and_then(Result::ok)
                .is_some_and(|f| Arc::ptr_eq(&f.open, &original.open))
        })
        .unwrap();
    v.close(fd).unwrap();
    let flush = receive(c, 25, 10);
    answer(c, &flush, &[]);
    let reused = v
        .open_at(AT_FDCWD, b"/replacement-batch", O_CREAT | 2, 0o600)
        .unwrap();
    assert_eq!(reused, fd);
    v.write(reused, b"replacement").unwrap();
    answer(c, &request, &vec![b'o'; 2 * PAGE_SIZE as usize]);
    let mut bytes = [0; 8];
    reads[1].copy_to(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"oooooooo");
    assert_eq!(file.fh, Some(9876));
}

#[test]
fn sequential_buffered_writes_accumulate_a_bounded_batch_before_using_existing_executor() {
    let (mut v, dev, original, file, executor) = setup(2, 0);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    for index in 0..16 {
        let mut operation = write(
            &v,
            &file,
            &original,
            Some(index * 65536),
            &vec![index as u8; 65536],
        );
        count(&mut operation, &mut v, 65536);
        drop(operation);
        assert!(file.attr.cache.writers.lock().unwrap().len() <= 2);
        assert_eq!(
            executor.jobs.lock().unwrap().len(),
            usize::from(index == 15)
        );
    }
    executor.step();
    let memory = trames_memory::Memory::default();
    for index in 0..8 {
        let request = wide_request(c, 16);
        assert_eq!(&request[48..56], &(index * 131072u64).to_le_bytes());
        assert_eq!(request[80], index as u8 * 2);
        assert_eq!(request[80 + 65536], index as u8 * 2 + 1);
        let reader =
            (index == 7).then(|| file.attr.layout.try_read(memory.memory_report()).unwrap());
        ack(c, &request);
        if index == 7 {
            drop(reader);
            executor.step();
        } else {
            assert!(
                executor.jobs.lock().unwrap().is_empty(),
                "owned slices do not need a new layout job"
            );
        }
    }
    assert!(!file.attr.cache.dirty());
    assert_eq!(file.attr.cache.buffered_pressure.load(Ordering::Relaxed), 0);
    assert_ne!(file.attr.dirty_times.load(Ordering::Relaxed), 0);
    let mut sync = file.sync(&v, false, 0, None, None).unwrap();
    executor.step();
    times(c, &executor);
    assert!(sync.take(&mut v).is_none());
    answer(c, &receive(c, 20, 10), &[]);
    count(&mut sync, &mut v, 0);
}

#[path = "writeback_batch_tests.rs"]
mod batch_tests;
#[path = "inline_reply_tests.rs"]
mod inline_tests;

#[test]
fn weak_writer_records_stay_bounded_when_small_writes_race_a_queued_batch() {
    let (mut v, _dev, original, file, executor) = setup(2, 0);
    let _actor = actor(&v, &executor);
    for _ in 0..1024 {
        let mut operation = write(&v, &file, &original, Some(0), b"data");
        count(&mut operation, &mut v, 4);
        drop(operation);
        assert!(file.attr.cache.writers.lock().unwrap().len() <= 2);
        assert!(executor.jobs.lock().unwrap().len() <= 1);
    }
    executor.close();
}

#[test]
fn writable_original_pins_remount_while_accepted_small_write_drains_on_sync() {
    let (mut v, dev, original, file, executor) = setup(2, 0);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let mut operation = write(&v, &file, &original, Some(0), b"accepted");
    count(&mut operation, &mut v, 8);
    drop(operation);
    assert!(executor.jobs.lock().unwrap().is_empty());
    assert_eq!(
        v.mount(None, b"/mnt", None, 32 | 4096 | mounts::MS_RDONLY, None),
        Err(Errno(16))
    );
    assert_eq!(file.mount.flags.get() & mounts::MS_RDONLY, 0);
    let mut sync = file.sync(&v, false, 0, None, None).unwrap();
    executor.step();
    let request = wide_request(c, 16);
    assert_eq!(&request[80..], b"accepted");
    ack(c, &request);
    executor.resume();
    times(c, &executor);
    assert!(sync.take(&mut v).is_none());
    let request = receive(c, 20, 10);
    answer(c, &request, &[]);
    count(&mut sync, &mut v, 0);
    assert_eq!(
        v.mount(None, b"/mnt", None, 32 | 4096 | mounts::MS_RDONLY, None),
        Err(Errno(16))
    );
    drop((sync, original, file));
    let fd = (0..32)
        .find(|fd| {
            v.shared_files()
                .lookup(*fd)
                .and_then(Result::ok)
                .is_some_and(|f| matches!(f.open.control, Some(events::SharedControl::FuseFile(_))))
        })
        .unwrap();
    v.close(fd).unwrap();
    let flush = receive(c, 25, 10);
    answer(c, &flush, &[]);
    receive(c, 18, 10);
    assert_eq!(
        v.mount(None, b"/mnt", None, 32 | 4096 | mounts::MS_RDONLY, None),
        Ok(())
    );
}

#[test]
fn implicit_close_records_retired_executor_error_without_claiming_dirty_flush_completed() {
    let (mut v, dev, original, file, executor) = setup(2, 0);
    let c = dev.connection().unwrap();
    {
        let _actor = actor(&v, &executor);
        let mut operation = write(&v, &file, &original, Some(0), b"retained");
        count(&mut operation, &mut v, 8);
    }
    drop(executor);
    file.flush_implicit(1);
    assert_eq!(c.read(8192), Err(Errno(11)));
    assert_eq!(
        file.attr.cache.check_error(&AtomicU64::new(0)),
        Err(Errno(5))
    );
    assert!(file.attr.cache.dirty());
}

#[test]
fn shared_batch_errors_remain_terminal_for_original_waiters_while_new_reads_retry() {
    let (v, dev, original, file, executor) = setup(2, 3 * PAGE_SIZE);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let reads = file
        .attr
        .cache
        .read_pages_as(
            &file,
            &original,
            0,
            3 * PAGE_SIZE as usize,
            file.reference.fs.caller(&v),
        )
        .unwrap();
    let request = wide_request(c, 15);
    c.write(&reply(id(&request), -5, &[])).unwrap();
    assert!(reads
        .iter()
        .all(|read| matches!(read.result(), Some(Err(Errno(5))))));
    let retry = file
        .attr
        .cache
        .read_pages_as(
            &file,
            &original,
            0,
            3 * PAGE_SIZE as usize,
            file.reference.fs.caller(&v),
        )
        .unwrap();
    let next = wide_request(c, 15);
    assert_ne!(id(&next), id(&request));
    answer(c, &next, &vec![b'n'; 3 * PAGE_SIZE as usize]);
    assert!(retry
        .iter()
        .all(|read| matches!(read.result(), Some(Ok(_)))));
    assert!(reads
        .iter()
        .all(|read| matches!(read.result(), Some(Err(Errno(5))))));
}

#[test]
fn only_the_last_original_page_waiter_cancels_an_unread_shared_request() {
    let (v, dev, original, file, executor) = setup(2, 2 * PAGE_SIZE);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let reads = file
        .attr
        .cache
        .read_pages_as(
            &file,
            &original,
            0,
            2 * PAGE_SIZE as usize,
            file.reference.fs.caller(&v),
        )
        .unwrap();
    let follower = file.read_page(&original, 1).unwrap();
    drop(reads);
    assert_ne!(c.poll(1).0 & 1, 0);
    drop(follower);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn late_batch_reply_cannot_overwrite_a_newer_dirty_page() {
    let (v, dev, original, file, executor) = setup(2, PAGE_SIZE);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let reads = file
        .attr
        .cache
        .read_pages_as(
            &file,
            &original,
            0,
            PAGE_SIZE as usize,
            file.reference.fs.caller(&v),
        )
        .unwrap();
    let request = wide_request(c, 15);
    file.attr
        .cache
        .store(0, &vec![b'n'; PAGE_SIZE as usize], PAGE_SIZE);
    file.attr.cache.buffered_write(0, b"newer");
    answer(c, &request, &vec![b'o'; PAGE_SIZE as usize]);
    let mut bytes = [0; 8];
    reads[0].copy_to(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"newernnn");
    assert!(file.attr.cache.dirty());
    file.attr.cache.resize(PAGE_SIZE, 0);
}

#[test]
fn resident_read_fast_path_retains_position_until_only_the_copied_prefix_commits() {
    let (mut v, _dev, original, file, executor) = setup(2, 0);
    let _actor = actor(&v, &executor);
    let mut operation = write(&v, &file, &original, Some(0), b"original");
    count(&mut operation, &mut v, 8);
    drop(operation);
    let mut read = file
        .operation(
            &v,
            &FileCommand::Read {
                offset: None,
                count: 8,
            },
            &original,
        )
        .unwrap()
        .unwrap();
    let Some(Ok(FileValue::Read(reply))) = read.take(&mut v) else {
        panic!("resident original read");
    };
    assert!(file.busy());
    assert_eq!(original.open.file_position.snapshot(), 0);
    let (bytes, mut position) = reply.into_parts();
    assert_eq!(bytes, b"original");
    position.record(3);
    drop(position);
    assert_eq!(original.open.file_position.snapshot(), 3);
    assert!(!file.busy());
    assert!(executor.jobs.lock().unwrap().is_empty());
}
