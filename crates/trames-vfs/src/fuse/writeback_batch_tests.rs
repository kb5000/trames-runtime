// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

type Completion = Arc<Mutex<Option<std::result::Result<(), MemoryError>>>>;

fn fill(v: &mut Vfs, file: &Arc<File>, original: &SharedFd, bytes: &[u8]) {
    let limit = file.reference.fs.connection.data_limit();
    for (index, chunk) in bytes.chunks(limit).enumerate() {
        let mut operation = write(v, file, original, Some((index * limit) as u64), chunk);
        count(&mut operation, v, chunk.len() as u64);
    }
}
fn full_flush(
    file: &Arc<File>,
    original: &SharedFd,
    executor: &Arc<Executor>,
) -> (Arc<writeback::Sync>, Completion) {
    let resource = Arc::new(writeback::Sync::with_options(
        file.clone(),
        original.clone(),
        Caller::default(),
        false,
        false,
        Some(file.attr.cache.writer().unwrap()),
        Some(executor.clone()),
    ));
    let done = Arc::new(Mutex::new(None));
    executor.submit(resource.clone(), Box::new(Done(done.clone())));
    (resource, done)
}
fn wire(c: &Connection, expected: &[u8]) -> Vec<u8> {
    let request = wide_request(c, 16);
    let offset = u64::from_le_bytes(request[48..56].try_into().unwrap()) as usize;
    let length = u32::from_le_bytes(request[56..60].try_into().unwrap()) as usize;
    assert!(length <= c.data_limit());
    assert_eq!(&request[40..48], &9876u64.to_le_bytes());
    assert_eq!(&request[80..], &expected[offset..offset + length]);
    request
}

#[test]
fn aborting_large_writeback_defers_each_failure_and_releases_the_original_inode_queue() {
    let (mut v, dev, original, file, executor) = setup(2, 0);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let bytes = vec![b'x'; 4 * 1024 * 1024];
    fill(&mut v, &file, &original, &bytes);
    let (_resource, done) = full_flush(&file, &original, &executor);
    executor.step(); // The original pressure writeback owns the inode queue.
    let _request = wire(c, &bytes);
    executor.step(); // The full flush waits in that same queue.
    assert!(executor.jobs.lock().unwrap().is_empty());
    c.abort();
    assert!(file.attr.cache.dirty());
    assert!(done.lock().unwrap().is_none());
    assert_eq!(executor.jobs.lock().unwrap().len(), 1);
    let mut steps = 0;
    while done.lock().unwrap().is_none() && steps < 64 {
        assert_eq!(executor.jobs.lock().unwrap().len(), 1);
        executor.step();
        steps += 1;
    }
    assert!(steps >= bytes.len() / c.data_limit());
    // The original pressure wave received ECONNABORTED. This queued flush
    // starts only after that wave retires and sees the disconnected transport.
    assert!(matches!(
        done.lock().unwrap().take(),
        Some(Err(MemoryError::BackingIo(107)))
    ));
    assert!(!file.attr.cache.dirty());
    assert!(!file.busy());
    assert!(executor.jobs.lock().unwrap().is_empty());
    assert_eq!(
        file.attr.cache.check_error(&file.writeback_seen),
        Err(Errno(107))
    );
    assert_eq!(file.attr.cache.check_error(&file.writeback_seen), Ok(()));
}

#[test]
fn original_request_keeps_its_first_abort_error_when_later_metadata_is_disconnected() {
    let (mut v, dev, original, file, executor) = setup(2, 0);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let bytes = vec![b'x'; 2 * PAGE_SIZE as usize];
    fill(&mut v, &file, &original, &bytes);
    let (_resource, done) = full_flush(&file, &original, &executor);
    executor.step();
    let _request = wire(c, &bytes);
    c.abort();
    executor.step();
    assert!(done.lock().unwrap().is_none());
    assert_eq!(executor.jobs.lock().unwrap().len(), 1);
    executor.step();
    assert!(matches!(
        done.lock().unwrap().take(),
        Some(Err(MemoryError::BackingIo(103)))
    ));
    assert!(!file.attr.cache.dirty());
    assert!(!file.busy());
    assert!(executor.jobs.lock().unwrap().is_empty());
}

#[test]
fn original_executor_exit_retires_an_already_deferred_transport_failure() {
    let (mut v, dev, original, file, executor) = setup(2, 0);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let bytes = vec![b'x'; 2 * PAGE_SIZE as usize];
    fill(&mut v, &file, &original, &bytes);
    let (_resource, done) = full_flush(&file, &original, &executor);
    executor.step();
    let _request = wire(c, &bytes);
    c.abort();
    assert!(done.lock().unwrap().is_none());
    assert_eq!(executor.jobs.lock().unwrap().len(), 1);
    executor.close();
    assert!(matches!(
        done.lock().unwrap().take(),
        Some(Err(MemoryError::BackingIo(5)))
    ));
    assert!(!file.busy());
    assert!(executor.jobs.lock().unwrap().is_empty());
}

#[test]
fn bounded_snapshots_need_layout_again_at_the_boundary_and_keep_wire_slices_ordered() {
    let (mut v, dev, original, file, executor) = setup(2, 0);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let bytes: Vec<_> = (0..2 * 1024 * 1024).map(|i| (i / 65536) as u8).collect();
    fill(&mut v, &file, &original, &bytes);
    assert_eq!(executor.jobs.lock().unwrap().len(), 1);
    executor.resume();
    let memory = trames_memory::Memory::default();
    for index in 0..16 {
        let request = wire(c, &bytes);
        assert_eq!(&request[48..56], &(index * 131072u64).to_le_bytes());
        let reader =
            (index % 8 == 7).then(|| file.attr.layout.try_read(memory.memory_report()).unwrap());
        ack(c, &request);
        if index % 8 == 7 {
            assert_eq!(executor.jobs.lock().unwrap().len(), 1);
            assert_eq!(
                c.read(8192),
                Err(Errno(11)),
                "next snapshot has not been admitted"
            );
            drop(reader);
            executor.step();
        } else {
            assert!(executor.jobs.lock().unwrap().is_empty());
        }
    }
    assert!(!file.attr.cache.dirty());
    assert_ne!(file.attr.dirty_times.load(Ordering::Relaxed), 0);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn non_page_aligned_wire_limits_preserve_every_byte_and_eof() {
    let (mut v, dev, original, file, executor) = setup_limit(2, 0, 8193);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let bytes: Vec<_> = (0..4 * PAGE_SIZE as usize + 17)
        .map(|i| (i * 31) as u8)
        .collect();
    fill(&mut v, &file, &original, &bytes);
    let (_resource, done) = full_flush(&file, &original, &executor);
    executor.resume();
    for (index, offset) in [0u64, 8193, 16386].into_iter().enumerate() {
        let request = wire(c, &bytes);
        assert_eq!(&request[48..56], &offset.to_le_bytes());
        ack(c, &request);
        if index == 2 {
            executor.resume();
        } else {
            assert!(executor.jobs.lock().unwrap().is_empty());
        }
    }
    times(c, &executor);
    assert!(matches!(done.lock().unwrap().take(), Some(Ok(()))));
    assert!(!file.attr.cache.dirty());
}

#[test]
fn failed_slice_retires_only_attempted_pages_and_still_writes_every_unsent_page() {
    for fault in [0, 1, 2] {
        let (mut v, dev, original, file, executor) = setup_limit(2, 0, PAGE_SIZE as u32);
        let c = dev.connection().unwrap();
        let _actor = actor(&v, &executor);
        let bytes: Vec<_> = (0..6 * PAGE_SIZE as usize)
            .map(|i| (i / PAGE_SIZE as usize) as u8)
            .collect();
        fill(&mut v, &file, &original, &bytes);
        let (_resource, done) = full_flush(&file, &original, &executor);
        executor.resume();
        ack(c, &wire(c, &bytes));
        assert!(executor.jobs.lock().unwrap().is_empty());
        let request = wire(c, &bytes);
        let (error, payload, expected) = match fault {
            0 => (-28, Vec::new(), 28),
            1 => (0, vec![0; 8], 5),
            _ => (0, vec![0; 7], 5),
        };
        let replied = c.write(&reply(id(&request), error, &payload));
        if fault == 2 {
            assert_eq!(
                replied,
                Err(Errno(22)),
                "transport rejects malformed size and completes the original waiter with EIO"
            );
        } else {
            replied.unwrap();
        }
        assert!(done.lock().unwrap().is_none());
        executor.resume();
        assert_eq!(
            file.attr
                .cache
                .dirty_pages()
                .iter()
                .map(|(i, _)| *i)
                .collect::<Vec<_>>(),
            vec![2, 3, 4, 5]
        );
        for index in 2..6 {
            let request = wire(c, &bytes);
            assert_eq!(&request[48..56], &(index * PAGE_SIZE).to_le_bytes());
            ack(c, &request);
            if index == 5 {
                executor.resume();
            }
        }
        times(c, &executor);
        assert!(
            matches!(done.lock().unwrap().take(), Some(Err(MemoryError::BackingIo(e))) if e == expected)
        );
        assert!(!file.attr.cache.dirty());
        assert_eq!(
            file.attr.cache.check_error(&file.writeback_seen),
            Err(Errno(expected))
        );
        assert_eq!(file.attr.cache.check_error(&file.writeback_seen), Ok(()));
    }
}

#[test]
fn mapped_stores_after_snapshot_survive_middle_acks_and_notification_retirement() {
    let (mut v, dev, original, file, executor) = setup_limit(2, 0, PAGE_SIZE as u32);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let bytes = vec![b'o'; 3 * PAGE_SIZE as usize];
    fill(&mut v, &file, &original, &bytes);
    let mappings = file
        .mapping_pages(original.clone(), 0, 3 * PAGE_SIZE, true, true)
        .unwrap();
    let (_resource, done) = full_flush(&file, &original, &executor);
    executor.resume();
    ack(c, &wire(c, &bytes));
    mappings[1].write(0, b"new").unwrap();
    file.attr.cache.invalidate(0, 3 * PAGE_SIZE);
    for index in 1..3 {
        let request = wire(c, &bytes); // Remaining wire bytes are the accepted snapshot.
        ack(c, &request);
        if index == 2 {
            executor.resume();
        }
    }
    times(c, &executor);
    assert!(matches!(done.lock().unwrap().take(), Some(Ok(()))));
    assert_eq!(
        file.attr
            .cache
            .dirty_pages()
            .iter()
            .map(|(i, _)| *i)
            .collect::<Vec<_>>(),
        vec![1]
    );
    let (_retry, done) = full_flush(&file, &original, &executor);
    executor.resume();
    let request = wide_request(c, 16);
    assert_eq!(&request[48..56], &PAGE_SIZE.to_le_bytes());
    assert_eq!(&request[80..83], b"new");
    ack(c, &request);
    executor.resume();
    assert!(matches!(done.lock().unwrap().take(), Some(Ok(()))));
    assert!(!file.attr.cache.dirty());
    drop(mappings);
}

#[test]
fn range_writeback_keeps_other_pages_and_times_dirty_until_a_full_barrier() {
    let (mut v, dev, original, file, executor) = setup_limit(2, 0, PAGE_SIZE as u32);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let bytes = vec![b'r'; 3 * PAGE_SIZE as usize];
    fill(&mut v, &file, &original, &bytes);
    let mut range = file
        .operation(
            &v,
            &FileCommand::SyncRange {
                offset: PAGE_SIZE + 9,
                length: PAGE_SIZE - 18,
                flags: 7,
            },
            &original,
        )
        .unwrap()
        .unwrap();
    executor.resume();
    let request = wire(c, &bytes);
    assert_eq!(&request[48..56], &PAGE_SIZE.to_le_bytes());
    assert_eq!(request.len(), 80 + PAGE_SIZE as usize);
    ack(c, &request);
    executor.resume();
    count(&mut range, &mut v, 0);
    assert_eq!(c.read(8192), Err(Errno(11)));
    assert_ne!(file.attr.dirty_times.load(Ordering::Relaxed), 0);
    assert_eq!(
        file.attr
            .cache
            .dirty_pages()
            .iter()
            .map(|(i, _)| *i)
            .collect::<Vec<_>>(),
        vec![0, 2]
    );
    let (_resource, done) = full_flush(&file, &original, &executor);
    executor.resume();
    for index in [0u64, 2] {
        let request = wire(c, &bytes);
        assert_eq!(&request[48..56], &(index * PAGE_SIZE).to_le_bytes());
        ack(c, &request);
        executor.resume();
    }
    times(c, &executor);
    assert!(matches!(done.lock().unwrap().take(), Some(Ok(()))));
}

#[test]
fn mapping_close_upgrades_queued_or_inflight_pressure_writeback_without_duplicate_jobs() {
    for late in [false, true] {
        let (mut v, dev, original, file, executor) = setup_limit(2, 0, PAGE_SIZE as u32);
        let c = dev.connection().unwrap();
        let _actor = actor(&v, &executor);
        let bytes = vec![b'u'; 8 * PAGE_SIZE as usize];
        fill(&mut v, &file, &original, &bytes);
        let writer = file.attr.cache.writer().unwrap();
        if !late {
            writeback::background(&writer);
        }
        assert_eq!(executor.jobs.lock().unwrap().len(), 1);
        executor.resume();
        let memory = trames_memory::Memory::default();
        for index in 0..8 {
            let reader = (index == 7 && late)
                .then(|| file.attr.layout.try_read(memory.memory_report()).unwrap());
            ack(c, &wire(c, &bytes));
            if index == 7 {
                if late {
                    writeback::background(&writer);
                }
                assert_eq!(executor.jobs.lock().unwrap().len(), usize::from(late));
                drop(reader);
                executor.resume();
            }
        }
        times(c, &executor);
        assert_eq!(file.attr.dirty_times.load(Ordering::Relaxed), 0);
        assert!(executor.jobs.lock().unwrap().is_empty());
    }
}

#[test]
fn completed_data_wave_leaves_a_metadata_only_close_barrier() {
    let (mut v, dev, original, file, executor) = setup_limit(2, 0, PAGE_SIZE as u32);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let bytes = vec![b't'; 8 * PAGE_SIZE as usize];
    fill(&mut v, &file, &original, &bytes);
    executor.resume();
    for index in 0..8 {
        ack(c, &wire(c, &bytes));
        if index == 7 {
            executor.resume();
        }
    }
    assert!(!file.attr.cache.dirty());
    assert_ne!(file.attr.dirty_times.load(Ordering::Relaxed), 0);
    assert_eq!(c.read(8192), Err(Errno(11)));
    writeback::background(&file.attr.cache.writer().unwrap());
    executor.resume();
    times(c, &executor);
    assert_eq!(file.attr.dirty_times.load(Ordering::Relaxed), 0);
}

#[test]
fn retirement_after_an_intermediate_ack_preserves_unsent_dirty_data_and_is_terminal() {
    let (mut v, dev, original, file, executor) = setup_limit(2, 0, PAGE_SIZE as u32);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let bytes = vec![b'e'; 3 * PAGE_SIZE as usize];
    fill(&mut v, &file, &original, &bytes);
    let (resource, done) = full_flush(&file, &original, &executor);
    executor.resume();
    ack(c, &wire(c, &bytes));
    let late = wire(c, &bytes);
    resource.failed(MemoryError::BackingIo(5));
    assert!(matches!(
        done.lock().unwrap().take(),
        Some(Err(MemoryError::BackingIo(5)))
    ));
    assert_eq!(file.attr.cache.dirty_pages().len(), 3);
    // A reply to the withdrawn original request cannot publish a third WRITE.
    let mut payload = [0; 8];
    payload[..4].copy_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
    let _ = c.write(&reply(id(&late), 0, &payload));
    assert_eq!(c.read(8192), Err(Errno(11)));
    executor.close();
}

#[test]
fn retained_snapshot_and_implicit_close_never_switch_to_a_reused_numeric_fd() {
    let (mut v, dev, original, file, executor) = setup_limit(2, 0, PAGE_SIZE as u32);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let bytes = vec![b'f'; 3 * PAGE_SIZE as usize];
    fill(&mut v, &file, &original, &bytes);
    let (resource, done) = full_flush(&file, &original, &executor);
    executor.resume();
    ack(c, &wire(c, &bytes));
    let fd = (0..32)
        .find(|fd| {
            v.shared_files()
                .lookup(*fd)
                .and_then(Result::ok)
                .is_some_and(|f| Arc::ptr_eq(&f.open, &original.open))
        })
        .unwrap();
    v.close(fd).unwrap();
    let reused = v
        .open_at(AT_FDCWD, b"/snapshot-replacement", O_CREAT | 2, 0o600)
        .unwrap();
    assert_eq!(reused, fd);
    v.write(reused, b"replacement").unwrap();
    // Admit the implicit close, which parks behind the same original wave.
    executor.resume();
    for index in 1..3 {
        ack(c, &wire(c, &bytes));
        if index == 2 {
            executor.resume();
        }
    }
    times(c, &executor);
    assert!(matches!(done.lock().unwrap().take(), Some(Ok(()))));
    executor.resume();
    let flush = receive(c, 25, 10);
    assert_eq!(&flush[40..48], &9876u64.to_le_bytes());
    answer(c, &flush, &[]);
    assert_eq!(v.pread(reused, 11, 0).unwrap(), b"replacement");
    drop((resource, original, file));
    receive(c, 18, 10);
}

#[test]
fn metadata_error_after_data_only_writeback_reaches_fsync_once_without_a_false_flush() {
    let (mut v, dev, original, file, executor) = setup_limit(2, 0, PAGE_SIZE as u32);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let bytes = vec![b'm'; 8 * PAGE_SIZE as usize];
    fill(&mut v, &file, &original, &bytes);
    executor.resume();
    for index in 0..8 {
        ack(c, &wire(c, &bytes));
        if index == 7 {
            executor.resume();
        }
    }
    let mut sync = file.sync(&v, false, 0, None, None).unwrap();
    executor.resume();
    let request = receive(c, 4, 10);
    c.write(&reply(id(&request), -5, &[])).unwrap();
    executor.resume();
    assert!(matches!(sync.take(&mut v), Some(Err(Errno(5)))));
    assert_eq!(c.read(8192), Err(Errno(11)));
    let mut retry = file.sync(&v, false, 0, None, None).unwrap();
    answer(c, &receive(c, 20, 10), &[]);
    count(&mut retry, &mut v, 0);
}

#[test]
fn retirement_during_request_publication_withdraws_the_uninstalled_original_handle() {
    struct Retire {
        resource: Arc<writeback::Sync>,
        armed: std::sync::atomic::AtomicBool,
    }
    impl trames_shared::IoWake for Retire {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            if self.armed.swap(false, Ordering::Relaxed) {
                self.resource.failed(MemoryError::BackingIo(5));
            }
        }
    }
    let (mut v, dev, original, file, executor) = setup_limit(2, 0, PAGE_SIZE as u32);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    fill(
        &mut v,
        &file,
        &original,
        &vec![b'p'; 3 * PAGE_SIZE as usize],
    );
    let (resource, done) = full_flush(&file, &original, &executor);
    let wake: Arc<dyn trames_shared::IoWake> = Arc::new(Retire {
        resource,
        armed: std::sync::atomic::AtomicBool::new(true),
    });
    let signal = IoSignal::new(0, Arc::downgrade(&wake));
    let _subscription = c.subscribe(&signal);
    // The readiness wake runs after queue publication and before request()
    // returns its handle, without a test thread or a scheduling assumption.
    executor.resume();
    assert!(matches!(
        done.lock().unwrap().take(),
        Some(Err(MemoryError::BackingIo(5)))
    ));
    assert_eq!(c.read(8192), Err(Errno(11)));
    assert_eq!(file.attr.cache.dirty_pages().len(), 3);
    assert!(executor.jobs.lock().unwrap().is_empty());
}
