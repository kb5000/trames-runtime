// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

#[test]
fn sync_write_publishes_its_position_only_when_the_original_sync_succeeds() {
    for error in [0, -38, -5] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let (paths, fd) = open_file(&v, c, 2);
        let target = v
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        let write = waiting(FileWork::new(
            &paths,
            target.clone(),
            FileCommand::WriteSync {
                bytes: b"abcdef".to_vec(),
                offset: None,
                data_only: false,
            },
        ));
        let write = no_capabilities(c, write);
        answer(c, &receive(c, 16, 10), &6u64.to_le_bytes());
        let write = waiting(write);
        let sync = receive(c, 20, 10);
        assert_eq!(
            target.0.open.file_position.snapshot(),
            0,
            "WRITE alone cannot commit a synchronized syscall's f_pos"
        );
        let seek = waiting(FileWork::new(
            &paths,
            target,
            FileCommand::Seek {
                offset: 0,
                whence: 1,
            },
        ));
        assert!(!seek.ready());
        c.write(&reply(id(&sync), error, &[])).unwrap();
        if error == -5 {
            assert!(matches!(finish(write), Err(Errno(5))));
        } else {
            assert!(matches!(finish(write), Ok(FileValue::Count(6))));
        }
        assert!(seek.ready());
        assert!(
            matches!(finish(seek), Ok(FileValue::Count(n)) if n == if error == -5 { 0 } else { 6 })
        );
    }
}
#[test]
fn read_copyout_retains_the_original_ofd_and_commits_only_its_copied_prefix() {
    for copied in [0usize, 2, 6] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let (paths, fd) = open_file(&v, c, 2);
        let files = v.shared_files();
        let duplicate = files.duplicate(fd, 0, false).unwrap().unwrap();
        let target = files.lookup(fd).unwrap().unwrap().file_target().unwrap();
        let work = waiting(FileWork::new(
            &paths,
            target.clone(),
            FileCommand::Read {
                count: 6,
                offset: None,
            },
        ));
        let request = receive(c, 15, 10);
        answer(c, &request, b"abcdef");
        let FileValue::Read(reply) = finish(work).unwrap() else {
            panic!("accepted positional read")
        };
        let (bytes, mut position) = reply.into_parts();
        assert_eq!(bytes, b"abcdef");
        assert_eq!(
            target.0.open.file_position.snapshot(),
            0,
            "daemon completion does not commit guest copyout"
        );
        let seek = waiting(
            paths
                .fuse_file_work(
                    duplicate,
                    FileCommand::Seek {
                        offset: 0,
                        whence: 1,
                    },
                )
                .unwrap()
                .unwrap(),
        );
        assert!(!seek.ready());
        position.record(copied);
        assert_eq!(
            target.0.open.file_position.snapshot(),
            0,
            "the original position transaction is still held"
        );
        drop(position);
        assert!(seek.ready());
        assert!(matches!(finish(seek), Ok(FileValue::Count(n)) if n == copied as u64));
        assert_eq!(target.0.open.file_position.snapshot(), copied as u64);
    }
}

fn attributes(size: u64) -> [u8; 104] {
    let mut out = [0; 104];
    out[16..].copy_from_slice(&entry(10, 210, 0o100600)[40..]);
    out[24..32].copy_from_slice(&size.to_le_bytes());
    out
}
fn size_request(c: &Connection, mut work: FileWork, handle: bool) -> (FileWork, Vec<u8>) {
    let capabilities = receive(c, 22, 10);
    c.write(&reply(id(&capabilities), -61, &[])).unwrap();
    work = waiting(work);
    let refresh = receive(c, 3, 10);
    assert_eq!(&refresh[40..44], &u32::from(handle).to_le_bytes());
    if handle {
        assert_eq!(&refresh[48..56], &9876u64.to_le_bytes());
    }
    answer(c, &refresh, &attributes(8));
    work = waiting(work);
    let request = receive(c, 4, 10);
    (work, request)
}

#[test]
fn truncate_open_keeps_the_original_slot_hidden_until_setattr_succeeds() {
    for succeeds in [true, false] {
        let (mut v, dev) = mounted();
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        let files = FileEpoch::default().capture(&v, true);
        assert!(paths
            .open_at_resolve(AT_FDCWD, b"/mnt/data", O_TRUNC, 0, 0, &files)
            .is_none());
        let work = paths.take_open_work().unwrap();
        answer(c, &receive(c, 1, 1), &entry(10, 210, 0o100600));
        let work = waiting(work);
        let open = receive(c, 14, 10);
        assert_eq!(&open[40..44], &O_LARGEFILE.to_le_bytes());
        let mut handle = [0; 16];
        handle[..8].copy_from_slice(&9876u64.to_le_bytes());
        answer(c, &open, &handle);
        let work = waiting(work);
        let (work, truncate) = size_request(c, work, false);
        assert_eq!(&truncate[40..44], &(8u32 | 512).to_le_bytes());
        assert_eq!(&truncate[48..56], &[0; 8]);
        assert_eq!(&truncate[56..64], &[0; 8]);
        let other = v
            .open_at(AT_FDCWD, b"/occupied", O_CREAT | 2, 0o600)
            .unwrap();
        assert_eq!(
            v.mount(None, b"/mnt", None, 4096 | 32 | 1, None),
            Err(Errno(16))
        );
        if succeeds {
            answer(c, &truncate, &attributes(0));
            let FileValue::Count(fd) = finish(work).unwrap() else {
                panic!()
            };
            assert!((fd as u32) < other);
            assert_eq!(v.flags(fd as u32).unwrap() & O_TRUNC, 0);
            let read_only = v
                .shared_files()
                .lookup(fd as u32)
                .unwrap()
                .unwrap()
                .file_target()
                .unwrap();
            assert!(matches!(
                finish(FileWork::new(&paths, read_only, FileCommand::Truncate(1))),
                Err(Errno(22))
            ));
        } else {
            c.write(&reply(id(&truncate), -28, &[])).unwrap();
            assert!(matches!(finish(work), Err(Errno(28))));
            let release = receive(c, 18, 10);
            assert_eq!(&release[40..48], &9876u64.to_le_bytes());
            answer(c, &release, &[]);
            receive(c, 2, 10);
            let reclaimed = v
                .open_at(AT_FDCWD, b"/reclaimed", O_CREAT | 2, 0o600)
                .unwrap();
            assert!(
                reclaimed < other,
                "failed open releases its original reservation"
            );
        }
    }
}

#[test]
fn fd_truncate_uses_the_original_handle_and_daemon_size_for_all_aliases() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_file(&v, c, 2);
    let original = v.shared_files().lookup(fd).unwrap().unwrap();
    let target = original.file_target().unwrap();
    let work = waiting(FileWork::new(
        &paths,
        target.clone(),
        FileCommand::Truncate(3),
    ));
    let (work, request) = size_request(c, work, true);
    assert_eq!(&request[40..44], &(8u32 | 64 | 512).to_le_bytes());
    assert_eq!(&request[48..56], &9876u64.to_le_bytes());
    assert_eq!(&request[56..64], &3u64.to_le_bytes());
    answer(c, &request, &attributes(5));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    assert!(matches!(
        finish(FileWork::new(
            &paths,
            target,
            FileCommand::Seek {
                offset: 0,
                whence: 2
            }
        )),
        Ok(FileValue::Count(5))
    ));
}

#[test]
fn fd_truncate_reads_the_live_file_size_limit_and_delivers_its_signal() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_file(&v, c, 2);
    let target = v
        .shared_files()
        .lookup(fd)
        .unwrap()
        .unwrap()
        .file_target()
        .unwrap();
    // FileSizeLimit is shared with retained file contexts, not a stale snapshot.
    v.set_file_size_limit(2);
    let FileOutcome::Complete(reply) =
        FileWork::new(&paths, target.clone(), FileCommand::Truncate(3)).run()
    else {
        panic!()
    };
    assert!(matches!(reply.result, Err(Errno(27))));
    assert!(reply.file_size_signal);
    assert_eq!(c.read(8192), Err(Errno(11)));
    // Raising the same resource immediately admits the retained descriptor.
    v.set_file_size_limit(u64::MAX);
    let work = waiting(FileWork::new(&paths, target, FileCommand::Truncate(0)));
    let (work, request) = size_request(c, work, true);
    answer(c, &request, &attributes(0));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
}

#[test]
fn pathname_truncate_needs_no_daemon_open_or_descriptor_slot() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let next = v
        .open_at(AT_FDCWD, b"/ordinary", O_CREAT | 2, 0o600)
        .unwrap();
    v.close(next).unwrap();
    v.set_descriptor_limit(next);
    let paths = v.path_queries();
    let work = paths.truncate_path_work(b"/mnt/data", 3).unwrap().unwrap();
    answer(c, &receive(c, 1, 1), &entry(10, 210, 0o100600));
    let work = waiting(work);
    let (work, request) = size_request(c, work, false);
    assert_eq!(&request[56..64], &3u64.to_le_bytes());
    answer(c, &request, &attributes(3));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    receive(c, 2, 10);
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "no OPEN/FLUSH/RELEASE for pathname truncate"
    );
    v.set_descriptor_limit(next + 1);
    assert_eq!(v.open_at(AT_FDCWD, b"/ordinary", 2, 0).unwrap(), next);
}

fn written(count: u32) -> [u8; 8] {
    let mut reply = [0; 8];
    reply[..4].copy_from_slice(&count.to_le_bytes());
    reply
}

#[test]
fn write_privilege_removal_and_xattr_mutation_share_the_original_inode_transaction() {
    for removal_error in [false, true] {
        let (mut v, dev) = mounted();
        let c = dev.connection().unwrap();
        v.credentials.caps.effective &= !(1 << capabilities::FSETID);
        let (paths, fd) = open_file_with_mode(&v, c, 2, 0o106755);
        let target = v
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        let work = waiting(FileWork::new(
            &paths,
            target,
            FileCommand::Write {
                bytes: b"x".to_vec(),
                offset: Some(0),
            },
        ));
        let query = receive(c, 22, 10);
        assert_eq!(&query[48..], b"security.capability\0");
        let mut length = [0; 8];
        length[..4].copy_from_slice(&20u32.to_le_bytes());
        answer(c, &query, &length);
        let work = waiting(work);
        let remove = receive(c, 24, 10);
        let xattr = waiting(paths.namespace_work(NamespaceCall::Xattr {
            fd: fd as i32,
            path: None,
            follow: true,
            name: b"user.serial".to_vec(),
            value: Some(b"v".to_vec()),
            flags: 0,
        }));
        assert!(!xattr.ready());
        assert_eq!(c.read(8192), Err(Errno(11)));
        if removal_error {
            c.write(&reply(id(&remove), -61, &[])).unwrap();
            assert!(matches!(finish(work), Err(Errno(61))));
            assert_eq!(
                c.read(8192),
                Err(Errno(11)),
                "failed killpriv sends no data request"
            );
        } else {
            answer(c, &remove, &[]);
            let work = waiting(work);
            let refresh = receive(c, 3, 10);
            assert_eq!(
                &refresh[40..],
                &[0; 16],
                "killpriv is inode-based, not ATTR_FILE"
            );
            let mut attr = attributes(0);
            attr[76..80].copy_from_slice(&0o106755u32.to_le_bytes());
            answer(c, &refresh, &attr);
            let work = waiting(work);
            let mode = receive(c, 4, 10);
            assert_eq!(&mode[40..44], &1u32.to_le_bytes());
            assert_eq!(&mode[108..112], &0o100755u32.to_le_bytes());
            attr[76..80].copy_from_slice(&0o100755u32.to_le_bytes());
            answer(c, &mode, &attr);
            let work = waiting(work);
            let write = receive(c, 16, 10);
            assert_eq!(&write[40..48], &9876u64.to_le_bytes());
            assert_eq!(&write[80..], b"x");
            assert!(!xattr.ready());
            answer(c, &write, &written(1));
            assert!(matches!(finish(work), Ok(FileValue::Count(1))));
        }
        assert!(xattr.ready());
        let xattr = waiting(xattr);
        let request = receive(c, 21, 10);
        assert_eq!(&request[48..], b"user.serial\0v");
        answer(c, &request, &[]);
        assert!(matches!(finish(xattr), Ok(FileValue::Count(0))));
    }
}

#[test]
fn cancelling_an_unsent_xattr_does_not_interrupt_the_active_privilege_query() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_file(&v, c, 2);
    let target = v
        .shared_files()
        .lookup(fd)
        .unwrap()
        .unwrap()
        .file_target()
        .unwrap();
    let work = waiting(FileWork::new(
        &paths,
        target,
        FileCommand::Write {
            bytes: b"x".to_vec(),
            offset: None,
        },
    ));
    let query = receive(c, 22, 10);
    let xattr = waiting(paths.namespace_work(NamespaceCall::Xattr {
        fd: fd as i32,
        path: None,
        follow: true,
        name: b"user.cancel".to_vec(),
        value: None,
        flags: 0,
    }));
    assert!(!xattr.ready());
    drop(xattr);
    assert_eq!(c.read(8192), Err(Errno(11)));
    c.write(&reply(id(&query), -38, &[])).unwrap();
    let work = waiting(work);
    answer(c, &receive(c, 16, 10), &written(1));
    assert!(matches!(finish(work), Ok(FileValue::Count(1))));
}

#[test]
fn append_serializes_original_inode_updates_and_fcntl_uses_the_live_ofd_flags() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, a) = open_file(&v, c, 2 | 0x400);
    let (_, b) = open_file(&v, c, 2 | 0x400);
    let target_a = v
        .shared_files()
        .lookup(a)
        .unwrap()
        .unwrap()
        .file_target()
        .unwrap();
    let target_b = v
        .shared_files()
        .lookup(b)
        .unwrap()
        .unwrap()
        .file_target()
        .unwrap();
    let first = waiting(FileWork::new(
        &paths,
        target_a,
        FileCommand::Write {
            bytes: b"a".to_vec(),
            offset: None,
        },
    ));
    let first = no_capabilities(c, first);
    let first_request = receive(c, 16, 10);
    assert_eq!(&first_request[48..56], &0u64.to_le_bytes());
    let second = waiting(FileWork::new(
        &paths,
        target_b.clone(),
        FileCommand::Write {
            bytes: b"b".to_vec(),
            offset: None,
        },
    ));
    assert!(!second.ready());
    assert_eq!(c.read(8192), Err(Errno(11)));
    answer(c, &first_request, &written(1));
    assert!(matches!(finish(first), Ok(FileValue::Count(1))));
    assert!(second.ready());
    let second = waiting(second);
    let second_request = receive(c, 16, 10);
    assert_eq!(&second_request[48..56], &1u64.to_le_bytes());
    answer(c, &second_request, &written(1));
    assert!(matches!(finish(second), Ok(FileValue::Count(1))));
    assert!(matches!(
        finish(FileWork::new(
            &paths,
            target_b.clone(),
            FileCommand::Seek {
                offset: 0,
                whence: 1
            }
        )),
        Ok(FileValue::Count(2))
    ));
    v.fd_flags_snapshot().fcntl(b, 4, 2).unwrap();
    let plain = waiting(FileWork::new(
        &paths,
        target_b,
        FileCommand::Write {
            bytes: b"c".to_vec(),
            offset: Some(0),
        },
    ));
    let request = receive(c, 16, 10);
    assert_eq!(&request[48..56], &0u64.to_le_bytes());
    assert_eq!(
        u32::from_le_bytes(request[72..76].try_into().unwrap()) & 0x400,
        0
    );
    answer(c, &request, &written(1));
    assert!(matches!(finish(plain), Ok(FileValue::Count(1))));
}

#[test]
fn a_cancelled_inode_wait_never_consumes_or_interrupts_the_active_write() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_file(&v, c, 2);
    let target = v
        .shared_files()
        .lookup(fd)
        .unwrap()
        .unwrap()
        .file_target()
        .unwrap();
    let write = waiting(FileWork::new(
        &paths,
        target.clone(),
        FileCommand::Write {
            bytes: b"data".to_vec(),
            offset: Some(0),
        },
    ));
    let write = no_capabilities(c, write);
    let request = receive(c, 16, 10);
    let truncate = waiting(FileWork::new(&paths, target, FileCommand::Truncate(0)));
    assert!(!truncate.ready());
    drop(truncate);
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "unsent inode wait has no FUSE_INTERRUPT"
    );
    answer(c, &request, &written(4));
    assert!(matches!(finish(write), Ok(FileValue::Count(4))));
}

#[test]
fn stream_and_nonseekable_open_results_control_offsets_and_no_flush() {
    for daemon_flags in [4u32, 16] {
        let (mut v, dev) = mounted();
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        let files = FileEpoch::default().capture(&v, true);
        assert!(paths
            .open_at_resolve(AT_FDCWD, b"/mnt/data", 0, 0, 0, &files)
            .is_none());
        let work = paths.take_open_work().unwrap();
        answer(c, &receive(c, 1, 1), &entry(10, 210, 0o100600));
        let work = waiting(work);
        let mut open = [0; 16];
        open[..8].copy_from_slice(&9876u64.to_le_bytes());
        open[8..12].copy_from_slice(&(daemon_flags | 32).to_le_bytes());
        answer(c, &receive(c, 14, 10), &open);
        let FileValue::Count(fd) = finish(work).unwrap() else {
            panic!()
        };
        let target = v
            .shared_files()
            .lookup(fd as u32)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        for index in 0..2u64 {
            let read = waiting(FileWork::new(
                &paths,
                target.clone(),
                FileCommand::Read {
                    count: 1,
                    offset: None,
                },
            ));
            let request = receive(c, 15, 10);
            assert_eq!(
                &request[48..56],
                &(if daemon_flags == 16 { 0 } else { index }).to_le_bytes()
            );
            answer(c, &request, b"x");
            assert_eq!(finish(read).unwrap().into_bytes().unwrap(), b"x");
        }
        for command in [
            FileCommand::Seek {
                offset: 0,
                whence: 0,
            },
            FileCommand::Read {
                count: 1,
                offset: Some(0),
            },
        ] {
            assert!(matches!(
                finish(FileWork::new(&paths, target.clone(), command)),
                Err(Errno(29))
            ));
        }
        drop(target);
        v.close(fd as u32).unwrap();
        answer(c, &receive(c, 18, 10), &[]);
        receive(c, 2, 10);
        assert_eq!(
            c.read(8192),
            Err(Errno(11)),
            "FOPEN_NOFLUSH suppresses FLUSH only"
        );
    }
}

#[test]
fn synchronized_writes_wait_for_the_original_fsync_and_keep_the_byte_count() {
    for data_only in [false, true] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let (paths, fd) = open_file(&v, c, 2);
        let target = v
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        let write = waiting(FileWork::new(
            &paths,
            target.clone(),
            FileCommand::WriteSync {
                bytes: b"data".to_vec(),
                offset: None,
                data_only,
            },
        ));
        let write = no_capabilities(c, write);
        answer(c, &receive(c, 16, 10), &written(4));
        let write = waiting(write);
        let sync = receive(c, 20, 10);
        assert_eq!(&sync[40..48], &9876u64.to_le_bytes());
        assert_eq!(sync[48], u8::from(data_only));
        let next = waiting(FileWork::new(
            &paths,
            target.clone(),
            FileCommand::Write {
                bytes: b"next".to_vec(),
                offset: None,
            },
        ));
        assert!(
            !next.ready(),
            "the original OFD position remains held through sync"
        );
        c.write(&reply(id(&sync), -38, &[])).unwrap();
        assert!(matches!(finish(write), Ok(FileValue::Count(4))));
        assert!(next.ready());
        drop(next);
        // ENOSYS applies to this superblock's FSYNC opcode. A later explicit
        // sync completes with its own result and sends no redundant request.
        assert!(matches!(
            finish(FileWork::new(
                &paths,
                target,
                FileCommand::Sync {
                    data_only: !data_only
                }
            )),
            Ok(FileValue::Count(0))
        ));
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn zero_length_io_completes_without_a_daemon_request_or_sync() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_file(&v, c, 2);
    let target = v
        .shared_files()
        .lookup(fd)
        .unwrap()
        .unwrap()
        .file_target()
        .unwrap();
    assert!(finish(FileWork::new(
        &paths,
        target.clone(),
        FileCommand::Read {
            count: 0,
            offset: None
        }
    ))
    .unwrap()
    .into_bytes()
    .unwrap()
    .is_empty());
    assert!(matches!(
        finish(FileWork::new(
            &paths,
            target,
            FileCommand::WriteSync {
                bytes: Vec::new(),
                offset: None,
                data_only: false
            }
        )),
        Ok(FileValue::Count(0))
    ));
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn pathname_truncate_follows_a_daemon_symlink_to_the_original_ordinary_inode() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    v.import_file(b"/outside", b"ordinary".to_vec()).unwrap();
    let paths = v.path_queries();
    let work = paths.truncate_path_work(b"/mnt/link", 3).unwrap().unwrap();
    answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
    let work = waiting(work);
    answer(c, &receive(c, 5, 71), b"/outside");
    let outcome = work.run();
    let result = match outcome {
        FileOutcome::Complete(reply) => reply.result,
        FileOutcome::Layout(work) => finish(work.exclusive()),
        _ => panic!("resolved ordinary inode must enter its normal file operation"),
    };
    assert!(matches!(result, Ok(FileValue::Count(0))));
    let fd = v.open_at(AT_FDCWD, b"/outside", 0, 0).unwrap();
    assert_eq!(v.read(fd, 16).unwrap(), b"ord");
}
