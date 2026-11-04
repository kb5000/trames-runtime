// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::collections::BTreeSet;
use trames_memory::{Memory, Permissions, PAGE_SIZE};
fn target(v: &Vfs, fd: u32) -> FileTarget {
    v.shared_files()
        .lookup(fd)
        .unwrap()
        .unwrap()
        .file_target()
        .unwrap()
}
fn value(work: FileWork) -> Result<FileValue> {
    match work.run() {
        FileOutcome::Complete(reply) => {
            assert!(!reply.file_size_signal);
            reply.result
        }
        FileOutcome::Layout(_) => panic!("unexpected mapping-layout boundary"),
        FileOutcome::Waiting(_) => panic!("unexpected stream wait"),
        FileOutcome::Owner(_) => panic!("unexpected owner-only resource"),
    }
}
fn count(work: FileWork) -> Result<u64> {
    match value(work)? {
        FileValue::Count(n) => Ok(n),
        _ => panic!("expected scalar"),
    }
}
fn read_path(v: &mut Vfs, path: &[u8]) -> Vec<u8> {
    let fd = v.open_at(AT_FDCWD, path, 0, 0).unwrap();
    let result = v.read(fd, 65536).unwrap();
    v.close(fd).unwrap();
    result
}
fn disk() -> (std::path::PathBuf, Vfs) {
    let path = std::env::temp_dir().join(format!(
        "trames-files-{}-{}",
        std::process::id(),
        trames_memory::new_backing_identity()
    ));
    let v = Vfs::open_disk(&path, Default::default()).unwrap();
    (path, v)
}
#[test]
fn concurrent_growth_has_one_capacity_account_and_failed_growth_rolls_back() {
    for persistent in [false, true] {
        let (directory, mut v) = if persistent {
            let (p, v) = disk();
            (Some(p), v)
        } else {
            (None, Vfs::default())
        };
        let mut files = Vec::new();
        for i in 0..8 {
            files.push(
                v.open_at(AT_FDCWD, format!("/f{i}").as_bytes(), 2 | 0x40, 0o666)
                    .unwrap(),
            );
        }
        let base = v.capacity().used_bytes;
        v.set_storage_limits(StorageLimits {
            file_bytes: base + 4096,
            nodes: v.capacity().node_limit,
        })
        .unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let jobs: Vec<_> = files
            .iter()
            .map(|&fd| {
                let work = FileWork::from_vfs(
                    &v,
                    target(&v, fd),
                    FileCommand::Write {
                        bytes: vec![fd as u8; 1024],
                        offset: None,
                    },
                );
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    count(work)
                })
            })
            .collect();
        let results: Vec<_> = jobs.into_iter().map(|job| job.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| **r == Ok(1024)).count(), 4);
        assert_eq!(results.iter().filter(|r| **r == Err(Errno(28))).count(), 4);
        assert_eq!(v.capacity().used_bytes, base + 4096);
        let full = files
            .iter()
            .copied()
            .find(|&fd| v.seek(fd, 0, 2).unwrap() == 1024)
            .unwrap();
        assert_eq!(
            count(FileWork::from_vfs(
                &v,
                target(&v, full),
                FileCommand::Truncate(1 << 20)
            )),
            Err(Errno(28))
        );
        assert_eq!(v.seek(full, 0, 2).unwrap(), 1024);
        assert_eq!(v.capacity().used_bytes, base + 4096);
        assert_eq!(
            count(FileWork::from_vfs(
                &v,
                target(&v, full),
                FileCommand::Truncate(0)
            )),
            Ok(0)
        );
        assert_eq!(v.capacity().used_bytes, base + 3072);
        let empty = files
            .iter()
            .copied()
            .find(|&fd| v.seek(fd, 0, 2).unwrap() == 0)
            .unwrap();
        assert_eq!(
            count(FileWork::from_vfs(
                &v,
                target(&v, empty),
                FileCommand::Truncate(1024)
            )),
            Ok(0)
        );
        assert_eq!(v.capacity().used_bytes, base + 4096);
        drop(v);
        if let Some(directory) = directory {
            std::fs::remove_dir_all(directory).unwrap();
        }
    }
}
#[test]
fn concurrent_append_keeps_every_record_and_metadata_is_visible_without_epoch_copyback() {
    let mut v = Vfs::default();
    v.import_file(b"/append", Vec::new()).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(4));
    let jobs: Vec<_> = (0..4u32)
        .map(|id| {
            let fd = v.open_at(AT_FDCWD, b"/append", 2 | 0x400, 0).unwrap();
            let file = target(&v, fd);
            let paths = v.path_queries();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                for sequence in 0..128u32 {
                    let mut bytes = id.to_le_bytes().to_vec();
                    bytes.extend(sequence.to_le_bytes());
                    assert_eq!(
                        count(FileWork::new(
                            &paths,
                            file.clone(),
                            FileCommand::Write {
                                bytes,
                                offset: None
                            }
                        )),
                        Ok(8)
                    );
                }
                file
            })
        })
        .collect();
    let files: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
    let fd = v.open_at(AT_FDCWD, b"/append", 0, 0).unwrap();
    let bytes = v.read(fd, 8192).unwrap();
    assert_eq!(bytes.len(), 4 * 128 * 8);
    let records: BTreeSet<_> = bytes
        .chunks_exact(8)
        .map(|b| {
            (
                u32::from_le_bytes(b[..4].try_into().unwrap()),
                u32::from_le_bytes(b[4..].try_into().unwrap()),
            )
        })
        .collect();
    assert_eq!(records.len(), 4 * 128);
    assert_eq!(
        &v.stat_fd(fd).unwrap()[48..56],
        &(bytes.len() as u64).to_le_bytes()
    );
    assert!(v.stat_fd(fd).unwrap()[88..104].iter().any(|b| *b != 0));
    drop(files);
}
#[test]
fn unlink_keeps_the_original_byte_charge_until_the_last_accepted_description_drops() {
    let mut v = Vfs::default();
    v.import_file(b"/unlink", vec![9; 1024]).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/unlink", 2, 0).unwrap();
    let base = v.capacity().used_bytes;
    let accepted = FileWork::from_vfs(
        &v,
        target(&v, fd),
        FileCommand::Read {
            count: 1024,
            offset: None,
        },
    );
    v.unlink_at(AT_FDCWD, b"/unlink", false).unwrap();
    v.close(fd).unwrap();
    assert_eq!(v.capacity().used_bytes, base);
    assert!(matches!(value(accepted), Ok(FileValue::Bytes(bytes)) if bytes == vec![9; 1024]));
    assert_eq!(v.capacity().used_bytes, base - 1024);
}
#[test]
fn truncate_open_retains_the_resolved_inode_and_rolls_back_unpublished_reservations() {
    let mut v = Vfs::default();
    v.import_file(b"/file", b"original".to_vec()).unwrap();
    let mut epoch = FileEpoch::default();
    let files = epoch.capture(&v, true);
    let q = v.path_queries();
    assert!(q
        .open_at_resolve(AT_FDCWD, b"/file", 2 | 0x200, 0, 0, &files)
        .is_none());
    let abandoned = q.take_open_work().unwrap();
    drop(abandoned);
    assert_eq!(read_path(&mut v, b"/file"), b"original");
    assert!(q
        .open_at_resolve(AT_FDCWD, b"/file", 2 | 0x200, 0, 0, &files)
        .is_none());
    let work = q.take_open_work().unwrap();
    v.rename_at(AT_FDCWD, b"/file", AT_FDCWD, b"/old", 0)
        .unwrap();
    v.import_file(b"/file", b"replacement".to_vec()).unwrap();
    let fd = count(work).unwrap() as u32;
    assert!(v.pread(fd, 128, 0).unwrap().is_empty());
    assert!(read_path(&mut v, b"/old").is_empty());
    assert_eq!(read_path(&mut v, b"/file"), b"replacement");
    v.close(fd).unwrap();
    epoch.finish();
}
#[test]
fn file_copy_keeps_imported_input_across_output_layout_changes_and_fd_reuse() {
    let mut v = Vfs::default();
    v.import_file(b"/source", vec![0xa5; PAGE_SIZE as usize * 2])
        .unwrap();
    v.import_file(b"/target", vec![0; PAGE_SIZE as usize])
        .unwrap();
    let source = v.open_at(AT_FDCWD, b"/source", 2, 0).unwrap();
    let output = v.open_at(AT_FDCWD, b"/target", 2, 0).unwrap();
    let mut memory = Memory::default();
    memory
        .map_backed(
            0x10000,
            v.mapping_pages(output, 0, PAGE_SIZE, true, true).unwrap(),
            true,
            Permissions::RW,
            false,
        )
        .unwrap();
    let work = FileWork::from_vfs(
        &v,
        target(&v, output),
        FileCommand::Copy {
            input: target(&v, source),
            transfer: RefCell::new(FileCopy::new(Ok(Some(0)), Ok(Some(0)), 2 * PAGE_SIZE, true)),
        },
    );
    let FileOutcome::Layout(work) = work.run() else {
        panic!("mapped output growth needs a layout boundary");
    };
    v.pwrite(source, &vec![0x33; PAGE_SIZE as usize * 2], 0)
        .unwrap();
    v.close(source).unwrap();
    v.close(output).unwrap();
    let reused = v.open_at(AT_FDCWD, b"/source", 2, 0).unwrap();
    assert_eq!(reused, source);
    memory.commit_parallel().unwrap();
    assert!(
        matches!(value(work.exclusive()), Ok(FileValue::Transfer { count, from, to: Some(to) }) if count == 2 * PAGE_SIZE && from == count && to == count)
    );
    assert_eq!(
        read_path(&mut v, b"/target"),
        vec![0xa5; 2 * PAGE_SIZE as usize]
    );
    assert_eq!(
        read_path(&mut v, b"/source"),
        vec![0x33; 2 * PAGE_SIZE as usize]
    );
}
#[test]
fn syncfs_uses_the_descriptor_filesystem_even_in_another_root_context() {
    let (directory, mut v) = disk();
    v.import_file(b"/data", b"bytes".to_vec()).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/", O_DIRECTORY, 0).unwrap();
    let original = v
        .shared_files()
        .lookup(fd)
        .unwrap()
        .unwrap()
        .filesystem_target();
    let other = Vfs::default();
    let work = FileWork::from_vfs(&other, original.clone(), FileCommand::SyncFilesystem);
    assert_eq!(count(work), Ok(0));
    std::fs::remove_file(directory.join("manifest")).unwrap();
    std::fs::create_dir(directory.join("manifest")).unwrap();
    assert_eq!(
        count(FileWork::from_vfs(
            &other,
            original,
            FileCommand::SyncFilesystem
        )),
        Err(Errno(5))
    );
    drop((v, other));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn path_truncate_accepts_the_original_ofd_without_publishing_or_leaking_a_temporary_fd() {
    let mut v = Vfs::default();
    v.import_file(b"/file", b"original".to_vec()).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/file", 2, 0).unwrap();
    let before = v.fds.entries().len();
    let q = v.path_queries();
    let work = q.truncate_path_work(b"/file", 3).unwrap().unwrap();
    assert_eq!(v.fds.entries().len(), before);
    v.rename_at(AT_FDCWD, b"/file", AT_FDCWD, b"/old", 0)
        .unwrap();
    v.import_file(b"/file", b"replacement".to_vec()).unwrap();
    assert_eq!(count(work), Ok(0));
    assert_eq!(v.pread(fd, 32, 0).unwrap(), b"ori");
    assert_eq!(read_path(&mut v, b"/file"), b"replacement");
    assert_eq!(v.fds.entries().len(), before);
}
