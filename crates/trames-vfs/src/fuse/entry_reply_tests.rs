// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn root_fd(v: &Vfs, c: &Connection) -> u32 {
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(v, true);
    let fd = paths
        .open_at_resolve(AT_FDCWD, b"/mnt", O_PATH | O_DIRECTORY, 0, 0, &files)
        .expect("retained root O_PATH open needs no RPC")
        .unwrap();
    assert!(paths.statx_fd(fd).is_none());
    let work = paths.take_fuse_stat().unwrap();
    answer(
        c,
        &receive(c, 3, 1),
        &permission_tests::attributes(1, 0o040755, 0),
    );
    assert!(matches!(finish(work), Ok(FileValue::FuseStat(_, _))));
    fd
}

#[test]
fn root_lookup_updates_the_root_before_rejecting_a_named_alias() {
    for namespace in [false, true] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let fd = root_fd(&v, c);
        let paths = v.path_queries();
        let work = if namespace {
            waiting(paths.namespace_work(NamespaceCall::Mkdir {
                fd: AT_FDCWD,
                path: b"/mnt/new".to_vec(),
                mode: 0o700,
            }))
        } else {
            assert!(paths.statx_at(AT_FDCWD, b"/mnt/new", false).is_none());
            paths.take_fuse_stat().unwrap()
        };
        let mut entry = entry(1, 700, 0o040701);
        entry[8..16].copy_from_slice(&9u64.to_le_bytes());
        answer(c, &receive(c, 1, 1), &entry);
        assert!(matches!(finish(work), Err(Errno(5))));
        let (stat, _) = paths.statx_fd_cached(fd).unwrap().unwrap();
        assert_eq!(stat[16..20], 0o040701u32.to_le_bytes());
        assert_eq!(stat[8..16], 700u64.to_le_bytes());
        assert_eq!(
            v.statx_fd_cached(fd).unwrap().0,
            stat,
            "owner and worker use the retained inode cache"
        );
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}
#[test]
fn abandoned_root_lookup_and_getattr_still_update_the_retained_root() {
    for opcode in [1, 3, 4] {
        for cancel_first in [false, true] {
            let (v, dev) = mounted();
            let c = dev.connection().unwrap();
            let fd = root_fd(&v, c);
            let request = dev
                .daemon
                .get()
                .unwrap()
                .connection
                .request(opcode, 1, Caller::default(), &[0; 16])
                .unwrap();
            let message = receive(c, opcode, 1);
            let payload = if opcode == 1 {
                entry(1, 701, 0o040701).to_vec()
            } else {
                permission_tests::attributes(701, 0o040701, 0).to_vec()
            };
            if cancel_first {
                drop(request);
                answer(c, &message, &payload);
            } else {
                answer(c, &message, &payload);
                drop(request);
            }
            let stat = v.statx_fd_cached(fd).unwrap().0;
            assert_eq!(stat[16..20], 0o040701u32.to_le_bytes());
            assert_eq!(stat[8..16], 701u64.to_le_bytes());
            assert_eq!(c.read(8192), Err(Errno(11)));
        }
    }
}

#[test]
fn invalid_root_lookup_attributes_do_not_poison_but_valid_type_reuse_does() {
    for variant in 0..3 {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let fd = root_fd(&v, c);
        let paths = v.path_queries();
        assert!(paths.statx_at(AT_FDCWD, b"/mnt/new", false).is_none());
        let work = paths.take_fuse_stat().unwrap();
        let mut entry = entry(
            1,
            700,
            if variant == 0 {
                0o600
            } else if variant == 1 {
                0o040700
            } else {
                0o100600
            },
        );
        if variant == 1 {
            entry[48..56].copy_from_slice(&u64::MAX.to_le_bytes());
        }
        answer(c, &receive(c, 1, 1), &entry);
        assert!(matches!(finish(work), Err(Errno(5))));
        let cached = paths.statx_fd_cached(fd).unwrap();
        if variant == 2 {
            assert!(matches!(cached, Err(Errno(5))));
        } else {
            assert_eq!(cached.unwrap().0[16..20], 0o040755u32.to_le_bytes());
        }
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn invalid_atomic_and_fallback_creations_grant_no_resources_and_release_the_writer() {
    for fallback in [false, true] {
        for variant in 0..4 {
            let (mut v, dev) = mounted();
            let c = dev.connection().unwrap();
            let paths = v.path_queries();
            let files = FileEpoch::default().capture(&v, true);
            assert!(paths
                .open_at_resolve(AT_FDCWD, b"/mnt/new", O_CREAT | 0x80 | 2, 0o600, 0, &files)
                .is_none());
            let work = paths.take_open_work().unwrap();
            let lookup = receive(c, 1, 1);
            c.write(&reply(id(&lookup), -2, &[])).unwrap();
            let mut work = waiting(work);
            if fallback {
                let create = receive(c, 35, 1);
                c.write(&reply(id(&create), -38, &[])).unwrap();
                work = waiting(work);
            }
            let request = receive(c, if fallback { 8 } else { 35 }, 1);
            assert_eq!(v.mount(None, b"/mnt", None, 32 | 1, None), Err(Errno(16)));
            let mut entry = entry(
                if variant == 2 {
                    0
                } else if variant == 3 {
                    1
                } else {
                    80
                },
                180,
                if variant == 0 { 0o040755 } else { 0o100600 },
            )
            .to_vec();
            if variant == 1 {
                entry[48..56].copy_from_slice(&u64::MAX.to_le_bytes());
            }
            if !fallback {
                entry.extend([0; 16]);
            }
            answer(c, &request, &entry);
            assert!(matches!(finish(work), Err(Errno(5))));
            assert_eq!(c.read(8192), Err(Errno(11)));
            assert_eq!(v.mount(None, b"/mnt", None, 32 | 1, None), Ok(()));
        }
    }
}

#[test]
fn cancelled_invalid_entry_replies_never_invent_lookup_or_open_resources() {
    let (_dev, c) = start();
    for (opcode, kind) in [
        (1, 0),
        (6, 0o120000),
        (8, 0o100000),
        (9, 0o040000),
        (13, 0o100000),
        (35, 0o100000),
    ] {
        for variant in 0..5 {
            if opcode == 1 && variant == 4 {
                continue;
            }
            for cancel_first in [false, true] {
                let request = if opcode == 1 || opcode == 35 {
                    c.request(opcode, 1, Caller::default(), &[0; 16])
                } else {
                    c.request_entry(opcode, 1, Caller::default(), &[0; 16], kind)
                }
                .unwrap();
                let message = receive(&c, opcode, 1);
                let mode = if variant == 0 {
                    0o600
                } else if variant == 4 {
                    if kind == 0o040000 {
                        0o100600
                    } else {
                        0o040755
                    }
                } else {
                    kind.max(0o100000) | 0o600
                };
                let mut entry = entry(
                    if variant == 2 {
                        0
                    } else if variant == 3 {
                        1
                    } else {
                        80
                    },
                    180,
                    mode,
                )
                .to_vec();
                if variant == 1 {
                    entry[48..56].copy_from_slice(&u64::MAX.to_le_bytes());
                }
                if opcode == 35 {
                    entry.extend([0; 16]);
                }
                if cancel_first {
                    drop(request);
                    answer(&c, &message, &entry);
                } else {
                    answer(&c, &message, &entry);
                    drop(request);
                }
                assert_eq!(
                    c.read(8192),
                    Err(Errno(11)),
                    "opcode {opcode}, variant {variant}"
                );
            }
        }
    }
}

#[test]
fn an_invalid_namespace_parent_getattr_marks_its_retained_directory_bad() {
    let (mut v, dev) = mount_vfs_options(Vfs::default(), 0, ",default_permissions,allow_other");
    let c = dev.connection().unwrap();
    let fd = root_fd(&v, c);
    // The cached parent denies this caller write permission, so mutation must
    // refresh it. A granted cached parent does not require an extra GETATTR.
    v.credentials = Credentials::user(1000, 1000);
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Mkdir {
        fd: AT_FDCWD,
        path: b"/mnt/new".to_vec(),
        mode: 0o700,
    }));
    // Linux checks the existing leaf before checking the parent's mutation
    // permission. Preserve that lookup/error order in this refresh probe.
    let lookup = receive(c, 1, 1);
    c.write(&reply(id(&lookup), -2, &[])).unwrap();
    let work = waiting(work);
    answer(
        c,
        &receive(c, 3, 1),
        &permission_tests::attributes(1, 0o100600, 0),
    );
    assert!(matches!(finish(work), Err(Errno(5))));
    assert!(matches!(paths.statx_fd_cached(fd), Some(Err(Errno(5)))));
    assert_eq!(c.read(8192), Err(Errno(11)));
}
