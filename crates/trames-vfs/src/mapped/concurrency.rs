// SPDX-License-Identifier: GPL-3.0-or-later
//! Original mapped resources must survive executor handoff and concurrent users.
use super::*;
use std::sync::{mpsc, Barrier};
use trames_memory::{Memory, Permissions};

fn truncation_file(kind: u8) -> (Vfs, u32) {
    let mut v = Vfs::default();
    let fd = match kind {
        0 => v
            .open_at(AT_FDCWD, b"/truncate-private", 0x42, 0o600)
            .unwrap(),
        1 => {
            v.mkdir_at(AT_FDCWD, b"/tmp", 0o777).unwrap();
            v.mount(None, b"/tmp", Some(b"tmpfs"), 0, None).unwrap();
            v.open_at(AT_FDCWD, b"/tmp/private", 0x42, 0o600).unwrap()
        }
        _ => v.memfd_create(b"truncate-private", 0).unwrap(),
    };
    (v, fd)
}

#[test]
fn private_cow_survives_writes_and_partial_truncation_but_full_pages_refault_in_both_forks() {
    use trames_memory::{parallel::Registry, CpuMemory};
    for kind in 0..3 {
        let (mut v, fd) = truncation_file(kind);
        v.truncate_fd(fd, PAGE_SIZE * 2).unwrap();
        v.pwrite(fd, &[1], 0).unwrap();
        v.pwrite(fd, &[2], PAGE_SIZE).unwrap();
        let mut parent = Memory::default();
        parent
            .map_backed(
                0x10000,
                v.mapping_pages(fd, 0, PAGE_SIZE * 2, false, true).unwrap(),
                false,
                Permissions::RW,
                false,
            )
            .unwrap();
        parent.write_array(0x10000, [8]).unwrap();
        parent
            .with_write_chunk(0x11000, 1, |bytes| bytes[0] = 9)
            .unwrap();
        let mut child = parent.try_fork().unwrap();
        let mut registry = Registry::default();
        drop(parent.parallel_view(&mut registry).unwrap());
        v.pwrite(fd, &[3], 0).unwrap();
        v.pwrite(fd, &[4], PAGE_SIZE).unwrap();
        assert_eq!(parent.read_array::<1>(0x10000).unwrap(), [8]);
        assert_eq!(child.read_array::<1>(0x11000).unwrap(), [9]);
        // Linux keeps the COW of the partial EOF page, and unmaps private PTEs
        // for every complete page removed by truncation, including in a fork.
        v.truncate_fd(fd, 1).unwrap();
        assert!(matches!(
            parent.read_array::<1>(0x11000),
            Err(MemoryError::Bus(_))
        ));
        v.truncate_fd(fd, PAGE_SIZE * 2).unwrap();
        for memory in [&mut parent, &mut child] {
            assert_eq!(memory.read_array::<1>(0x10000).unwrap(), [8]);
            assert_eq!(memory.read_array::<1>(0x11000).unwrap(), [0]);
            assert_eq!(
                memory
                    .with_read_chunk(0x11000, 1, |bytes| bytes[0])
                    .unwrap()
                    .0,
                0
            );
            let view = memory.parallel_view(&mut registry).unwrap();
            assert_eq!(view.read_array::<1>(0x10000).unwrap(), [8]);
            assert_eq!(view.read_array::<1>(0x11000).unwrap(), [0]);
            drop(view);
        }
        parent.write_array(0x11000, [6]).unwrap();
        assert_eq!(parent.read_array::<1>(0x11000).unwrap(), [6]);
        assert_eq!(child.read_array::<1>(0x11000).unwrap(), [0]);
        assert_eq!(v.pread(fd, 1, PAGE_SIZE).unwrap(), [0]);
    }
}

#[test]
fn truncated_private_preflight_keeps_new_admission_and_retires_only_obsolete_rss() {
    use trames_memory::{Access, CgroupMemoryTarget, MemoryCgroup};
    for kind in 1..3 {
        let source = MemoryCgroup::new(None);
        let writer = MemoryCgroup::new(None);
        writer.set_limit(2 * PAGE_SIZE as usize);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(source.clone()));
        let _scope = target.scope();
        let (mut v, fd) = truncation_file(kind);
        v.pwrite(fd, &[1], 0).unwrap();
        let mut memory = Memory::default();
        memory.set_total_limit(PAGE_SIZE as usize).unwrap();
        memory
            .map_backed(
                0x10000,
                v.mapping_pages(fd, 0, PAGE_SIZE, false, true).unwrap(),
                false,
                Permissions::RW,
                false,
            )
            .unwrap();
        target.set(Some(writer.clone()));
        memory.write_array(0x10000, [9]).unwrap();
        target.set(Some(source.clone()));
        v.truncate_fd(fd, 0).unwrap();
        v.pwrite(fd, &[3], 0).unwrap();
        target.set(Some(writer.clone()));
        writer.set_limit(0);
        assert_eq!(
            memory.check(0x10000, 1, Access::Write),
            Err(MemoryError::Limit)
        );
        writer.set_limit(2 * PAGE_SIZE as usize);
        memory.check(0x10000, 1, Access::Write).unwrap();
        memory.check(0x10000, 1, Access::Write).unwrap();
        assert_eq!(memory.resident_bytes(), PAGE_SIZE as usize);
        assert_eq!(
            writer.current(),
            2 * PAGE_SIZE as usize,
            "old bytes and accepted new COW both exist"
        );
        memory
            .with_write_chunk(0x10000, 1, |bytes| bytes[0] = 7)
            .unwrap();
        assert_eq!(writer.current(), PAGE_SIZE as usize);
        assert_eq!(memory.resident_bytes(), PAGE_SIZE as usize);
        assert_eq!(memory.read_array::<1>(0x10000).unwrap(), [7]);
        assert_eq!(v.pread(fd, 1, 0).unwrap(), [3]);
        drop(memory);
        assert_eq!(writer.current(), 0);
    }
}

#[test]
fn simultaneous_first_mappings_retain_one_physical_page_per_offset() {
    for _ in 0..32 {
        let data = MappedData::new(FileData::memory(vec![17; PAGE_SIZE as usize * 4]), true);
        let start = Barrier::new(8);
        let mappings = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|worker| {
                    let data = &data;
                    let start = &start;
                    scope.spawn(move || {
                        start.wait();
                        let pages = if worker % 2 == 0 {
                            data.batch(0, PAGE_SIZE * 4).unwrap()
                        } else {
                            (0..4).map(|i| data.page(i * PAGE_SIZE).unwrap()).collect()
                        };
                        for page in &pages {
                            page.materialize().unwrap();
                        }
                        pages
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        for mapping in &mappings[1..] {
            for (first, peer) in mappings[0].iter().zip(mapping) {
                assert!(Arc::ptr_eq(first, peer));
                assert!(Arc::ptr_eq(&first.shared_page(), &peer.shared_page()));
            }
        }
    }
}

#[test]
fn mapping_handoff_retains_original_ofd_until_last_remote_unmap() {
    for shared in [false, true] {
        let mut vfs = Vfs::default();
        vfs.initialize_mounts().unwrap();
        let fd = vfs.open_at(AT_FDCWD, b"/handoff", 0x42, 0o600).unwrap();
        vfs.truncate_fd(fd, PAGE_SIZE * 3).unwrap();
        let contender = vfs.open_at(AT_FDCWD, b"/handoff", 0, 0).unwrap();
        vfs.flock(fd, 6).unwrap();
        let notify = vfs.inotify_init(O_NONBLOCK).unwrap();
        vfs.inotify_add(notify, b"/handoff", 8).unwrap();
        let mount = vfs
            .mounts
            .as_ref()
            .unwrap()
            .0
            .borrow()
            .root
            .identity
            .clone();
        let mut memory = Memory::default();
        memory
            .map_backed(
                0x10000,
                vfs.mapping_pages(fd, 0, PAGE_SIZE, shared, true).unwrap(),
                shared,
                Permissions::RW,
                false,
            )
            .unwrap();
        memory.write_array(0x10000, *b"original").unwrap();
        let mut child = memory.try_fork().unwrap();
        vfs.close(fd).unwrap();
        drop(memory);
        let (ready, reached) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            assert_eq!(child.read_array::<8>(0x10000).unwrap(), *b"original");
            child.write_array(0x10000, *b"modified").unwrap();
            // Extension constructs a new provider from the retained original
            // OFD, after its descriptor and original address space are gone.
            child
                .remap(0x10000, PAGE_SIZE, 0x20000, PAGE_SIZE * 2, false)
                .unwrap();
            child.write_array(0x21000, *b"extended").unwrap();
            child.sync_range(0x20000, PAGE_SIZE * 2).unwrap();
            ready.send(()).unwrap();
            wait.recv().unwrap();
            child.unmap(0x20000, PAGE_SIZE * 2).unwrap();
        });
        reached
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert_eq!(vfs.flock(contender, 6), Err(Errno(11)));
        assert_eq!(vfs.read(notify, 4096), Err(Errno(11)));
        // Both private and shared VMAs retain the original writable OFD.
        assert!(mount.writers.active());
        vfs.seek(contender, PAGE_SIZE as i64, 0).unwrap();
        assert_eq!(
            vfs.read(contender, 8).unwrap(),
            if shared {
                b"extended".as_slice()
            } else {
                &[0; 8]
            }
        );
        release.send(()).unwrap();
        worker.join().unwrap();
        assert!(!mount.writers.active());
        vfs.flock(contender, 6).unwrap();
        let event = vfs.read(notify, 4096).unwrap();
        assert_eq!(event.len(), 16);
        assert_eq!(u32::from_le_bytes(event[4..8].try_into().unwrap()), 8);
        assert_eq!(vfs.read(notify, 4096), Err(Errno(11)));
    }
}

#[test]
fn concurrent_mapping_writes_and_flushes_preserve_each_writers_final_bytes() {
    let mut vfs = Vfs::default();
    let fd = vfs.open_at(AT_FDCWD, b"/flush-race", 0x42, 0o600).unwrap();
    vfs.truncate_fd(fd, PAGE_SIZE).unwrap();
    let mapping = vfs
        .mapping_pages(fd, 0, PAGE_SIZE, true, true)
        .unwrap()
        .pop()
        .unwrap();
    let node = vfs
        .descriptor(fd)
        .unwrap()
        .open
        .borrow()
        .data_node()
        .unwrap();
    let page = match &node.borrow().content {
        Content::File(FileData::Mapped(data)) => data.page(0).unwrap(),
        _ => unreachable!(),
    };
    let start = Barrier::new(6);
    std::thread::scope(|scope| {
        for writer in 0..4 {
            let mapping = &mapping;
            let start = &start;
            scope.spawn(move || {
                start.wait();
                for sequence in 1..=1024u64 {
                    mapping.write(writer * 8, &sequence.to_le_bytes()).unwrap();
                }
            });
        }
        for _ in 0..2 {
            let node = &node;
            let page = &page;
            let start = &start;
            scope.spawn(move || {
                start.wait();
                for _ in 0..1024 {
                    let inode = node.borrow();
                    let Content::File(FileData::Mapped(data)) = &inode.content else {
                        unreachable!()
                    };
                    data.flush(0, page).unwrap();
                }
            });
        }
    });
    {
        let inode = node.borrow();
        let Content::File(FileData::Mapped(data)) = &inode.content else {
            unreachable!()
        };
        data.flush(0, &page).unwrap();
    }
    // Read the underlying file, not the mapping cache that could hide lost
    // writeback. Retire the final provider on a different executor as well.
    std::thread::spawn(move || drop(mapping)).join().unwrap();
    let node = vfs
        .descriptor(fd)
        .unwrap()
        .open
        .borrow()
        .data_node()
        .unwrap();
    let inode = node.borrow();
    let Content::File(FileData::Mapped(data)) = &inode.content else {
        unreachable!()
    };
    assert_eq!(
        data.data.borrow().read_at(0, 32).unwrap(),
        1024u64.to_le_bytes().repeat(4)
    );
}

#[test]
fn failed_writeback_keeps_dirty_bytes_for_retry() {
    let mut vfs = Vfs::default();
    let fd = vfs
        .open_at(AT_FDCWD, b"/writeback-source", 0x42, 0o600)
        .unwrap();
    vfs.truncate_fd(fd, PAGE_SIZE).unwrap();
    let node = vfs
        .descriptor(fd)
        .unwrap()
        .open
        .borrow()
        .data_node()
        .unwrap();
    // A read-through overlay source rejects writes before copy-up.
    let data = MappedData::new(FileData::Lower(node), true);
    let page = data.page(0).unwrap();
    page.with_bytes(|storage| storage.copy_write(0, b"retained"))
        .unwrap();
    page.dirty.store(true, Ordering::Relaxed);
    assert_eq!(data.flush(0, &page), Err(Errno(30)));
    assert!(page.dirty.load(Ordering::Relaxed));
    **data.data.borrow_mut() = FileData::memory(vec![0; PAGE_SIZE as usize]);
    data.flush(0, &page).unwrap();
    assert!(!page.dirty.load(Ordering::Relaxed));
    assert_eq!(data.data.borrow().read_at(0, 8).unwrap(), b"retained");
}
