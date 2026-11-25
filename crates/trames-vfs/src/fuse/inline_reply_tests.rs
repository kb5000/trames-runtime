// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

#[test]
fn mapped_layout_survives_independent_aliases_and_invalidation_until_the_last_view_drops() {
    let (v, _dev, original, file, executor) = setup(0, 2 * PAGE_SIZE);
    let _actor = actor(&v, &executor);
    assert!(file.mapped_layout().is_none());
    let first = file
        .mapping_pages(original.clone(), 0, 2 * PAGE_SIZE, true, false)
        .unwrap();
    let second = file
        .mapping_pages(original, 0, PAGE_SIZE, true, false)
        .unwrap();
    let retained = first[1].clone();
    assert!(file.mapped_layout().is_some());
    file.attr.cache.invalidate_all();
    drop(first);
    drop(second);
    assert!(file.mapped_layout().is_some());
    drop(retained);
    assert!(file.mapped_layout().is_none());
    file.attr.cache.invalidate_all();
    assert!(file.mapped_layout().is_none());
}

#[test]
fn read_publication_uses_existing_executor_only_while_the_original_mapping_is_retained() {
    let (v, dev, original, file, executor) = setup(0, 2 * PAGE_SIZE);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let mappings = file
        .mapping_pages(original.clone(), 0, PAGE_SIZE, true, false)
        .unwrap();
    let retained = mappings[0].clone();
    drop(mappings);
    let read = file.read_page(&original, 0).unwrap();
    answer(c, &receive(c, 15, 10), b"mapped");
    assert!(read.result().is_none());
    assert_eq!(executor.jobs.lock().unwrap().len(), 1);
    executor.step();
    assert!(matches!(read.result(), Some(Ok(_))));
    drop(retained);
    let read = file.read_page(&original, 1).unwrap();
    answer(c, &receive(c, 15, 10), b"ordinary");
    assert!(matches!(read.result(), Some(Ok(_))));
    assert!(executor.jobs.lock().unwrap().is_empty());
}

#[test]
fn cancelled_cross_page_write_never_publishes_its_unwritten_full_middle_page() {
    aborted_write(false);
}
#[test]
fn failed_edge_read_does_not_replace_the_original_middle_page_with_zeroes() {
    aborted_write(true);
}
fn aborted_write(fail: bool) {
    let (mut v, dev, original, file, executor) = setup(2, 3 * PAGE_SIZE);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let mut operation = write(
        &v,
        &file,
        &original,
        Some(1),
        &vec![b'x'; 3 * PAGE_SIZE as usize - 2],
    );
    assert!(operation.take(&mut v).is_none());
    let first = receive(c, 15, 10);
    let last = receive(c, 15, 10);
    assert_eq!(&first[48..56], &0u64.to_le_bytes());
    assert_eq!(&last[48..56], &(2 * PAGE_SIZE).to_le_bytes());
    if fail {
        c.write(&reply(id(&first), -5, &[])).unwrap();
        assert!(matches!(operation.take(&mut v), Some(Err(Errno(5)))));
    }
    drop(operation);
    assert!(!file.attr.cache.dirty());
    assert!(file.attr.cache.cached(PAGE_SIZE, 4).is_none());
    let mut interrupted = Vec::new();
    for _ in 0..if fail { 1 } else { 2 } {
        let request = receive(c, 36, 0);
        interrupted.push(u64::from_le_bytes(request[40..48].try_into().unwrap()));
    }
    interrupted.sort_unstable();
    let mut expected = if fail {
        vec![id(&last)]
    } else {
        vec![id(&first), id(&last)]
    };
    expected.sort_unstable();
    assert_eq!(interrupted, expected);
    if !fail {
        answer(c, &first, &vec![b'e'; PAGE_SIZE as usize]);
    }
    answer(c, &last, &vec![b'e'; PAGE_SIZE as usize]);
    assert!(file.attr.cache.cached(PAGE_SIZE, 4).is_none());
    let mut read = file
        .operation(
            &v,
            &FileCommand::Read {
                offset: Some(PAGE_SIZE),
                count: 4,
            },
            &original,
        )
        .unwrap()
        .unwrap();
    assert!(read.take(&mut v).is_none());
    let request = receive(c, 15, 10);
    assert_eq!(&request[48..56], &PAGE_SIZE.to_le_bytes());
    answer(c, &request, b"live");
    assert!(matches!(read.take(&mut v), Some(Ok(FileValue::Bytes(bytes))) if bytes == b"live"));
    assert!(!file.attr.cache.dirty());
}

#[test]
fn complete_cold_reply_can_move_once_while_original_page_followers_remain_usable() {
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
    answer(c, &receive(c, 15, 10), b"abc");
    let bytes = cache::Read::take_reply(&reads, 1, 2 * PAGE_SIZE as usize - 1).unwrap();
    assert_eq!(&bytes[..2], b"bc");
    assert!(bytes[2..].iter().all(|b| *b == 0));
    assert!(cache::Read::take_reply(&reads, 0, 8).is_none());
    let mut page = [1; PAGE_SIZE as usize];
    reads[0].copy_to(0, &mut page).unwrap();
    assert_eq!(&page[..3], b"abc");
    assert!(page[3..].iter().all(|b| *b == 0));
    assert_eq!(original.open.file_position.snapshot(), 0);
}

#[test]
fn reply_reuse_falls_back_when_new_dirty_bytes_won_before_publication() {
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
    let request = receive(c, 15, 10);
    file.attr
        .cache
        .buffered_write(PAGE_SIZE, &vec![b'n'; PAGE_SIZE as usize]);
    answer(c, &request, &vec![b'o'; 2 * PAGE_SIZE as usize]);
    assert!(cache::Read::take_reply(&reads, 0, 2 * PAGE_SIZE as usize).is_none());
    let mut bytes = [0; 4];
    reads[1].copy_to(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"nnnn");
}

#[test]
fn eof_clamped_at_publication_survives_growth_before_copyout() {
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
    let request = receive(c, 15, 10);
    file.attr.lock().unwrap()[8..16].copy_from_slice(&3u64.to_le_bytes());
    answer(c, &request, &vec![b'o'; 2 * PAGE_SIZE as usize]);
    file.attr.lock().unwrap()[8..16].copy_from_slice(&(2 * PAGE_SIZE).to_le_bytes());
    assert!(cache::Read::take_reply(&reads, 0, 2 * PAGE_SIZE as usize).is_none());
    let mut page = [1; PAGE_SIZE as usize];
    reads[0].copy_to(0, &mut page).unwrap();
    assert_eq!(&page[..3], b"ooo");
    assert!(page[3..].iter().all(|b| *b == 0));
}

struct LeaseChecked {
    layout: Arc<trames_memory::layout::Layout>,
    owner: trames_memory::MemoryReport,
    checked: Arc<std::sync::atomic::AtomicBool>,
    done: Arc<Mutex<Option<std::result::Result<(), MemoryError>>>>,
}
impl SyncCompletion for LeaseChecked {
    fn complete(self: Box<Self>, result: std::result::Result<(), MemoryError>) {
        self.checked.store(
            self.layout.try_read(self.owner.clone()).is_some(),
            Ordering::Relaxed,
        );
        *self.done.lock().unwrap() = Some(result);
    }
}
#[test]
fn quiet_reply_completes_after_its_original_inline_layout_lease_is_released() {
    reply_lease(false);
}
#[test]
fn contended_reply_parks_on_the_existing_executor_without_reissuing_data() {
    reply_lease(true);
}
fn reply_lease(contended: bool) {
    let (mut v, dev, original, file, executor) = setup(2, 0);
    let c = dev.connection().unwrap();
    let _actor = actor(&v, &executor);
    let mut operation = write(&v, &file, &original, Some(0), b"owned");
    count(&mut operation, &mut v, 5);
    drop(operation);
    let memory = trames_memory::Memory::default();
    let checked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done = Arc::new(Mutex::new(None));
    let resource = writeback::Sync::with_options(
        file.clone(),
        original,
        Caller::default(),
        false,
        false,
        Some(file.attr.cache.writer().unwrap()),
        Some(executor.clone()),
    );
    executor.submit(
        Arc::new(resource),
        Box::new(LeaseChecked {
            layout: file.attr.layout.clone(),
            owner: memory.memory_report(),
            checked: checked.clone(),
            done: done.clone(),
        }),
    );
    executor.step();
    let request = receive(c, 16, 10);
    let reader = contended.then(|| file.attr.layout.try_read(memory.memory_report()).unwrap());
    ack(c, &request);
    if contended {
        assert!(file.attr.cache.dirty());
        assert_eq!(executor.jobs.lock().unwrap().len(), 1);
        assert_eq!(c.read(8192), Err(Errno(11)));
        drop(reader);
        executor.step();
    } else {
        assert!(!file.attr.cache.dirty());
        assert!(executor.jobs.lock().unwrap().is_empty());
    }
    times(c, &executor);
    assert!(matches!(done.lock().unwrap().take(), Some(Ok(()))));
    assert!(checked.load(Ordering::Relaxed));
}
