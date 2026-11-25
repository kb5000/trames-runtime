// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn attributes(c: &Connection, node: u64, mode: u32, uid: u32) {
    let mut body = [0; 104];
    body[16..].copy_from_slice(&entry(node, node + 100, mode)[40..]);
    body[84..88].copy_from_slice(&uid.to_le_bytes());
    answer(c, &receive(c, 3, node), &body);
}
fn call(paths: &PathQueries, call: NamespaceCall) -> FileWork {
    waiting(paths.namespace_work(call))
}
fn count(work: FileWork) {
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
}
fn absent(c: &Connection, parent: u64, work: FileWork) -> FileWork {
    let request = receive(c, 1, parent);
    c.write(&reply(id(&request), -2, &[])).unwrap();
    waiting(work)
}
fn forgotten(c: &Connection, expected: &[u64]) {
    let mut nodes = Vec::new();
    for _ in expected {
        let request = c.read(8192).unwrap();
        assert_eq!(op(&request), 2);
        nodes.push(u64::from_le_bytes(request[16..24].try_into().unwrap()));
    }
    nodes.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(nodes, expected);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn socket_bind_retains_original_ofd_inode_and_exclusion_across_daemon_wait() {
    for kind in [1, 2] {
        let (mut v, dev) = mounted();
        let c = dev.connection().unwrap();
        let fd = v.local_create(kind, 0).unwrap();
        let socket = v.descriptor_factory().local_operation(fd).unwrap().unwrap();
        let paths = v.path_queries();
        let address = b"\x01\0/mnt/socket\0".to_vec();
        let work = call(
            &paths,
            NamespaceCall::LocalBind {
                socket: socket.clone(),
                address: address.clone(),
            },
        );
        attributes(c, 1, 0o40755, 0);
        let work = waiting(work);
        let work = absent(c, 1, work);
        let request = receive(c, 8, 1);
        assert_eq!(
            u32::from_le_bytes(request[40..44].try_into().unwrap()) & 0o170000,
            0o140000
        );
        let second = call(
            &paths,
            NamespaceCall::LocalBind {
                socket: socket.clone(),
                address: b"\x01\0/mnt/other\0".to_vec(),
            },
        );
        assert!(!second.ready());
        assert_eq!(c.read(8192), Err(Errno(11)));
        v.close(fd).unwrap();
        assert_eq!(v.eventfd(0, 0).unwrap(), fd);
        answer(c, &request, &entry(80, 180, 0o140755));
        count(work);
        assert_eq!(
            v.umount(b"/mnt", 0),
            Err(Errno(16)),
            "bound pathname retains its original mount"
        );
        assert!(second.ready());
        assert!(matches!(finish(second), Err(Errno(22))));
        assert_eq!(
            c.read(8192),
            Err(Errno(11)),
            "live socket retains its weak-cache inode"
        );
        if kind == 1 {
            v.descriptor_factory().local_listen(&socket, 1).unwrap();
        }
        let client_fd = v.local_create(kind, 0).unwrap();
        let client = v
            .descriptor_factory()
            .local_operation(client_fd)
            .unwrap()
            .unwrap();
        let connecting = call(
            &paths,
            NamespaceCall::LocalConnect {
                socket: client.clone(),
                address: address.clone(),
                identity: [1, 0, 0],
            },
        );
        answer(c, &receive(c, 1, 1), &entry(80, 180, 0o140755));
        let FileValue::LocalConnection(connection) = finish(connecting).unwrap() else {
            panic!("accepted connect");
        };
        connection.attempt().unwrap();
        receive(c, 2, 80); // The connect lookup releases its own reference.
        if kind == 2 {
            let send = call(
                &paths,
                NamespaceCall::LocalDatagram {
                    socket: client.clone(),
                    address: Some(address),
                },
            );
            answer(c, &receive(c, 1, 1), &entry(80, 180, 0o140755));
            let FileValue::LocalDatagram(target) = finish(send).unwrap() else {
                panic!("accepted datagram");
            };
            let selected = std::sync::OnceLock::from(target);
            assert_eq!(
                client.send_datagram(
                    &selected,
                    b"packet",
                    0,
                    Default::default(),
                    [1, 0, 0],
                    false,
                    || panic!("target was already accepted")
                ),
                Some(Ok(6))
            );
        }
        drop(connection);
    }
}

#[test]
fn socket_bind_cancellation_releases_only_its_own_admission() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let fd = v.descriptor_factory().local_create(1, 0).unwrap();
    let socket = v.descriptor_factory().local_operation(fd).unwrap().unwrap();
    let paths = v.path_queries();
    let command = || NamespaceCall::LocalBind {
        socket: socket.clone(),
        address: b"\x01\0/mnt/socket\0".to_vec(),
    };
    let work = call(&paths, command());
    attributes(c, 1, 0o40755, 0);
    let work = waiting(work);
    let work = absent(c, 1, work);
    let request = receive(c, 8, 1);
    let blocked = call(&paths, command());
    assert!(!blocked.ready());
    drop(work);
    assert!(blocked.ready());
    answer(c, &request, &entry(80, 180, 0o140755));
    forgotten(c, &[80]);
    drop(blocked);
    assert_eq!(socket.name(false).unwrap(), [1, 0]);
}

#[test]
fn nested_mkdir_retains_parent_and_passes_original_mask_and_name() {
    let (mut v, dev) = mounted();
    v.set_umask(0o027);
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = call(
        &paths,
        NamespaceCall::Mkdir {
            fd: AT_FDCWD,
            path: b"/mnt/parent/newdir".to_vec(),
            mode: 0o777,
        },
    );
    assert_eq!(
        v.umount(b"/mnt", 0),
        Err(Errno(16)),
        "accepted namespace lookup pins its original mount"
    );
    answer(c, &receive(c, 1, 1), &entry(70, 170, 0o40777));
    let work = waiting(work);
    let work = absent(c, 70, work);
    let mkdir = receive(c, 9, 70);
    assert_eq!(&mkdir[40..44], &0o750u32.to_le_bytes());
    assert_eq!(&mkdir[44..48], &0o027u32.to_le_bytes());
    assert_eq!(&mkdir[48..], b"newdir\0");
    answer(c, &mkdir, &entry(71, 171, 0o40750));
    count(work);
    forgotten(c, &[70, 71]);
}

#[test]
fn creation_samples_shared_umask_after_the_final_lookup_wait() {
    for directory in [true, false] {
        let (v, dev) = mounted();
        v.set_umask(0o027);
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        let command = if directory {
            NamespaceCall::Mkdir {
                fd: AT_FDCWD,
                path: b"/mnt/new".to_vec(),
                mode: 0o777,
            }
        } else {
            NamespaceCall::Mknod {
                fd: AT_FDCWD,
                path: b"/mnt/new".to_vec(),
                mode: 0o100666,
                device: 0,
            }
        };
        let work = call(&paths, command);
        attributes(c, 1, 0o40755, 0);
        let work = waiting(work);
        let lookup = receive(c, 1, 1);
        v.set_umask(0o077);
        c.write(&reply(id(&lookup), -2, &[])).unwrap();
        let work = waiting(work);
        let request = receive(c, if directory { 9 } else { 8 }, 1);
        let mode: u32 = if directory { 0o700 } else { 0o100600 };
        assert_eq!(&request[40..44], &mode.to_le_bytes());
        let mask_offset = if directory { 44 } else { 48 };
        assert_eq!(
            &request[mask_offset..mask_offset + 4],
            &0o077u32.to_le_bytes()
        );
        answer(
            c,
            &request,
            &entry(80, 180, if directory { 0o40700 } else { mode }),
        );
        count(work);
        forgotten(c, &[80]);
    }
}

#[test]
fn creation_cancellation_forgets_late_reply_and_releases_mount() {
    for opcode in [6, 8, 9] {
        let (mut v, dev) = mounted();
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        let (command, mode) = match opcode {
            6 => (
                NamespaceCall::Symlink {
                    target: b"../data".to_vec(),
                    fd: AT_FDCWD,
                    path: b"/mnt/link".to_vec(),
                },
                0o120777,
            ),
            8 => (
                NamespaceCall::Mknod {
                    fd: AT_FDCWD,
                    path: b"/mnt/file".to_vec(),
                    mode: 0o100600,
                    device: 0,
                },
                0o100600,
            ),
            9 => (
                NamespaceCall::Mkdir {
                    fd: AT_FDCWD,
                    path: b"/mnt/directory".to_vec(),
                    mode: 0o700,
                },
                0o40700,
            ),
            _ => unreachable!(),
        };
        let work = call(&paths, command);
        attributes(c, 1, 0o40755, 0);
        let work = waiting(work);
        let work = absent(c, 1, work);
        let request = receive(c, opcode, 1);
        if opcode == 6 {
            assert_eq!(&request[40..], b"link\0../data\0");
        }
        drop(work);
        answer(c, &request, &entry(80, 180, mode));
        forgotten(c, &[80]);
        v.umount(b"/mnt", 0).unwrap();
    }
}

#[test]
fn unlink_checks_kind_and_sticky_ownership_before_daemon_mutation() {
    for local in [false, true] {
        let (mut v, dev) = mount_vfs_options(
            Vfs::default(),
            0,
            if local { ",default_permissions" } else { "" },
        );
        v.credentials.fsuid = 1000;
        v.credentials.caps.effective = 0;
        let c = dev.connection().unwrap();
        for (mode, parent, expected) in [(0o40755, 0o40777, 21), (0o100600, 0o41777, 1)] {
            let paths = v.path_queries();
            let work = call(
                &paths,
                NamespaceCall::Unlink {
                    fd: AT_FDCWD,
                    path: b"/mnt/target".to_vec(),
                    directory: false,
                },
            );
            attributes(c, 1, parent, 12);
            let work = waiting(work);
            let mut target = entry(80, 180, mode);
            target[108..112].copy_from_slice(&13u32.to_le_bytes());
            answer(c, &receive(c, 1, 1), &target);
            if expected == 1 && !local {
                let work = waiting(work);
                answer(c, &receive(c, 10, 1), &[]);
                assert!(matches!(finish(work), Ok(FileValue::Count(0))));
            } else {
                assert!(matches!(finish(work), Err(Errno(error)) if error == expected));
            }
            forgotten(c, &[80]);
        }
    }
}

#[test]
fn rename_keeps_both_directory_operands_until_daemon_completes() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = call(
        &paths,
        NamespaceCall::Rename {
            oldfd: AT_FDCWD,
            old: b"/mnt/old".to_vec(),
            newfd: AT_FDCWD,
            new: b"/mnt/parent/new".to_vec(),
            flags: 0,
        },
    );
    answer(c, &receive(c, 1, 1), &entry(70, 170, 0o40755));
    let work = waiting(work);
    attributes(c, 1, 0o40755, 0);
    let work = waiting(work);
    answer(c, &receive(c, 1, 1), &entry(80, 180, 0o100600));
    let work = waiting(work);
    let missing = receive(c, 1, 70);
    c.write(&reply(id(&missing), -2, &[])).unwrap();
    let work = waiting(work);
    let rename = receive(c, 12, 1);
    assert_eq!(&rename[40..48], &70u64.to_le_bytes());
    assert_eq!(&rename[48..], b"old\0new\0");
    answer(c, &rename, &[]);
    count(work);
    forgotten(c, &[70, 80]);
}

#[test]
fn rename_noreplace_and_exchange_preserve_original_errors() {
    for (flags, existing, expected) in [(1, true, 17), (2, false, 2)] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        let work = call(
            &paths,
            NamespaceCall::Rename {
                oldfd: AT_FDCWD,
                old: b"/mnt/old".to_vec(),
                newfd: AT_FDCWD,
                new: b"/mnt/new".to_vec(),
                flags,
            },
        );
        attributes(c, 1, 0o40755, 0);
        let work = waiting(work);
        answer(c, &receive(c, 1, 1), &entry(80, 180, 0o100600));
        let work = waiting(work);
        attributes(c, 1, 0o40755, 0);
        let work = waiting(work);
        let lookup = receive(c, 1, 1);
        if existing {
            answer(c, &lookup, &entry(81, 181, 0o100600));
        } else {
            c.write(&reply(id(&lookup), -2, &[])).unwrap();
        }
        assert!(matches!(finish(work), Err(Errno(error)) if error == expected));
        forgotten(c, if existing { &[80, 81] } else { &[80] });
    }
}

#[test]
fn directory_fd_mutation_survives_numeric_reuse() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_directory(&v, c, false);
    let work = call(
        &paths,
        NamespaceCall::Mkdir {
            fd: fd as i32,
            path: b"child".to_vec(),
            mode: 0o755,
        },
    );
    v.shared_files().close_range(fd, fd, 0, 1).unwrap();
    let replacement = v
        .open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
        .unwrap();
    assert_eq!(fd, replacement);
    let work = absent(c, 70, work);
    let request = receive(c, 9, 70);
    assert_eq!(&request[48..], b"child\0");
    answer(c, &request, &entry(71, 171, 0o40755));
    count(work);
    receive(c, 2, 71);
    answer(c, &receive(c, 29, 70), &[]);
    receive(c, 2, 70);
}

#[test]
fn creation_trailing_slash_and_existing_final_keep_vfs_errors() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    for command in [
        NamespaceCall::Symlink {
            fd: AT_FDCWD,
            path: b"/mnt/missing/".to_vec(),
            target: b"data".to_vec(),
        },
        NamespaceCall::Mknod {
            fd: AT_FDCWD,
            path: b"/mnt/missing/".to_vec(),
            mode: 0o100600,
            device: 0,
        },
    ] {
        let work = call(&paths, command);
        attributes(c, 1, 0o40755, 0);
        let work = waiting(work);
        let lookup = receive(c, 1, 1);
        c.write(&reply(id(&lookup), -2, &[])).unwrap();
        assert!(matches!(finish(work), Err(Errno(2))));
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
    let work = call(
        &paths,
        NamespaceCall::Mkdir {
            fd: AT_FDCWD,
            path: b"/mnt/existing".to_vec(),
            mode: 0o755,
        },
    );
    attributes(c, 1, 0o40755, 0);
    let work = waiting(work);
    answer(c, &receive(c, 1, 1), &entry(80, 180, 0o100600));
    assert!(matches!(finish(work), Err(Errno(17))));
    forgotten(c, &[80]);
    assert!(matches!(
        finish(paths.namespace_work(NamespaceCall::Mknod {
            fd: AT_FDCWD,
            path: b"/mnt/dir".to_vec(),
            mode: 0o40700,
            device: 0
        })),
        Err(Errno(1))
    ));
}

#[test]
fn invalid_created_node_returns_eio_and_releases_mount_write_admission() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = call(
        &paths,
        NamespaceCall::Mkdir {
            fd: AT_FDCWD,
            path: b"/mnt/new".to_vec(),
            mode: 0o700,
        },
    );
    assert_eq!(v.mount(None, b"/mnt", None, 32 | 1, None), Err(Errno(16)));
    attributes(c, 1, 0o40755, 0);
    let work = absent(c, 1, waiting(work));
    answer(c, &receive(c, 9, 1), &entry(0, 0, 0o40700));
    assert!(matches!(finish(work), Err(Errno(5))));
    assert_eq!(c.read(8192), Err(Errno(11)));
    assert_eq!(v.mount(None, b"/mnt", None, 32 | 1, None), Ok(()));
}

#[test]
fn rename2_enosys_becomes_einval_and_is_cached_only_after_a_valid_attempt() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    for first in [true, false] {
        let work = call(
            &paths,
            NamespaceCall::Rename {
                oldfd: AT_FDCWD,
                old: b"/mnt/old".to_vec(),
                newfd: AT_FDCWD,
                new: b"/mnt/new".to_vec(),
                flags: 2,
            },
        );
        attributes(c, 1, 0o40755, 0);
        let work = waiting(work);
        answer(c, &receive(c, 1, 1), &entry(80, 180, 0o100600));
        let work = waiting(work);
        attributes(c, 1, 0o40755, 0);
        let work = waiting(work);
        answer(c, &receive(c, 1, 1), &entry(81, 181, 0o100600));
        let work = if first {
            let work = waiting(work);
            let request = receive(c, 45, 1);
            c.write(&reply(id(&request), -38, &[])).unwrap();
            work
        } else {
            work
        };
        assert!(matches!(finish(work), Err(Errno(22))));
        forgotten(c, &[80, 81]);
    }
}
