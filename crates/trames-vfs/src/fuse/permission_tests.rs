// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
fn mounted_local() -> (Vfs, Arc<Device>) {
    let (mut v, dev) = mount_vfs_options(Vfs::default(), 0, ",allow_other,default_permissions");
    v.credentials = Credentials::user(1000, 1000);
    (v, dev)
}
pub(super) fn attributes(ino: u64, mode: u32, uid: u32) -> [u8; 104] {
    let mut a = [0; 104];
    a[..8].copy_from_slice(&3600u64.to_le_bytes());
    a[16..24].copy_from_slice(&ino.to_le_bytes());
    a[76..80].copy_from_slice(&mode.to_le_bytes());
    a[80..84].copy_from_slice(&1u32.to_le_bytes());
    a[84..88].copy_from_slice(&uid.to_le_bytes());
    a
}
pub(super) fn lookup_entry(id: u64, mode: u32) -> [u8; 128] {
    let mut e = entry(id, id + 100, mode);
    e[24..32].copy_from_slice(&3600u64.to_le_bytes());
    e
}
fn root(c: &Connection, work: FileWork) -> FileWork {
    answer(c, &receive(c, 3, 1), &attributes(1, 0o040755, 0));
    waiting(work)
}
fn access(v: &Vfs, path: &[u8], mask: u32) -> FileWork {
    let paths = v.path_queries();
    assert!(paths
        .access_at(AT_FDCWD, path, mask, false, false)
        .is_none());
    paths.take_fuse_stat().unwrap()
}
#[test]
fn local_access_uses_cached_modes_without_an_access_rpc_and_refreshes_a_denial_once() {
    for (mask, refreshed, ok) in [
        (4, 0o100644, true),
        (2, 0o100666, true),
        (2, 0o100644, false),
    ] {
        let (v, dev) = mounted_local();
        let c = dev.connection().unwrap();
        let work = root(c, access(&v, b"/mnt/file", mask));
        answer(c, &receive(c, 1, 1), &lookup_entry(70, 0o100644));
        let work = if mask == 2 {
            let work = waiting(work);
            answer(c, &receive(c, 3, 70), &attributes(170, refreshed, 0));
            work
        } else {
            work
        };
        let value = finish(work);
        assert!(if ok {
            matches!(value, Ok(FileValue::Count(0)))
        } else {
            matches!(value, Err(Errno(13)))
        });
        receive(c, 2, 70);
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}
#[test]
fn local_search_checks_dot_and_dotdot_before_traversing_a_private_directory() {
    for suffix in [b"/./child".as_slice(), b"/../child"] {
        let (v, dev) = mounted_local();
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        let mut path = b"/mnt/private".to_vec();
        path.extend(suffix);
        assert!(paths.statx_at(AT_FDCWD, &path, false).is_none());
        let work = root(c, paths.take_fuse_stat().unwrap());
        answer(c, &receive(c, 1, 1), &lookup_entry(70, 0o040700));
        let work = waiting(work);
        answer(c, &receive(c, 3, 70), &attributes(170, 0o040700, 0));
        assert!(matches!(finish(work), Err(Errno(13))));
        receive(c, 2, 70);
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}
#[test]
fn pending_local_chdir_keeps_its_caller_credentials_and_cancellation_releases_lookup() {
    for cancel in [false, true] {
        let (mut v, dev) = mounted_local();
        let c = dev.connection().unwrap();
        let work = waiting(
            v.path_queries()
                .namespace_work(NamespaceCall::Chdir(b"/mnt/private".to_vec())),
        );
        let work = root(c, work);
        answer(c, &receive(c, 1, 1), &lookup_entry(70, 0o040700));
        let work = waiting(work);
        let request = receive(c, 3, 70);
        v.credentials = Credentials::default();
        if cancel {
            drop(work);
            let interrupt = receive(c, 36, 0);
            answer(c, &interrupt, &[]);
            receive(c, 2, 70);
            answer(c, &request, &attributes(170, 0o040700, 0));
        } else {
            answer(c, &request, &attributes(170, 0o040700, 0));
            assert!(matches!(finish(work), Err(Errno(13))));
            receive(c, 2, 70);
        }
        assert_eq!(v.cwd().unwrap(), b"/");
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}
#[test]
fn local_xattr_permissions_precede_the_per_opcode_unsupported_cache() {
    let (v, dev) = mounted_local();
    let c = dev.connection().unwrap();
    let work = waiting(v.path_queries().namespace_work(NamespaceCall::GetXattr {
        fd: AT_FDCWD,
        path: Some(b"/mnt/readable".to_vec()),
        follow: true,
        name: Some(b"user.test".to_vec()),
        capacity: 1,
    }));
    let work = root(c, work);
    answer(c, &receive(c, 1, 1), &lookup_entry(69, 0o100644));
    let work = waiting(work);
    let request = receive(c, 22, 69);
    c.write(&reply(id(&request), -38, &[])).unwrap();
    assert!(matches!(finish(work), Err(Errno(95))));
    receive(c, 2, 69);
    let work = waiting(v.path_queries().namespace_work(NamespaceCall::GetXattr {
        fd: AT_FDCWD,
        path: Some(b"/mnt/secret".to_vec()),
        follow: true,
        name: Some(b"user.test".to_vec()),
        capacity: 1,
    }));
    answer(c, &receive(c, 1, 1), &lookup_entry(70, 0o100600));
    let work = waiting(work);
    answer(c, &receive(c, 3, 70), &attributes(170, 0o100600, 0));
    assert!(matches!(finish(work), Err(Errno(13))));
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}
#[test]
fn local_chmod_denial_sends_no_setattr_and_does_not_keep_a_mount_writer() {
    let (mut v, dev) = mounted_local();
    let c = dev.connection().unwrap();
    let work = waiting(v.path_queries().namespace_work(NamespaceCall::Chmod {
        fd: AT_FDCWD,
        path: Some(b"/mnt/file".to_vec()),
        mode: 0o600,
        nofollow: false,
        empty: false,
    }));
    let work = root(c, work);
    answer(c, &receive(c, 1, 1), &lookup_entry(70, 0o100644));
    assert!(matches!(finish(work), Err(Errno(1))));
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
    v.credentials = Credentials::default();
    v.mount(None, b"/mnt", None, 4096 | 32 | 1, None).unwrap();
}
#[test]
fn access_local_modes_use_real_ids_across_lookup_and_permission_waits() {
    let (mut v, dev) = mounted_local();
    let c = dev.connection().unwrap();
    v.credentials = Credentials::default();
    v.credentials.uid = 1000;
    let work = root(c, access(&v, b"/mnt/secret", 4));
    answer(c, &receive(c, 1, 1), &lookup_entry(70, 0o100600));
    let work = waiting(work);
    let request = receive(c, 3, 70);
    assert_eq!(&request[24..28], &1000u32.to_le_bytes());
    answer(c, &request, &attributes(170, 0o100600, 0));
    assert!(matches!(finish(work), Err(Errno(13))));
    receive(c, 2, 70);
    assert_eq!(v.credentials.fsuid, 0);
}

#[test]
fn parent_permission_wait_preserves_an_open_reservation_and_checks_control_access_mode() {
    for flags in [0, 3] {
        let (v, dev) = mounted_local();
        let c = dev.connection().unwrap();
        let files = FileEpoch::default().capture(&v, true);
        let paths = v.path_queries();
        assert!(paths
            .open_at_resolve(AT_FDCWD, b"/mnt/file", flags, 0, 0, &files)
            .is_none());
        let work = root(c, paths.take_open_work().unwrap());
        answer(c, &receive(c, 1, 1), &lookup_entry(70, 0o100644));
        let work = waiting(work);
        if flags == 3 {
            answer(c, &receive(c, 3, 70), &attributes(170, 0o100644, 0));
            assert!(matches!(finish(work), Err(Errno(13))));
            receive(c, 2, 70);
        } else {
            let mut handle = [0; 16];
            handle[..8].copy_from_slice(&70u64.to_le_bytes());
            answer(c, &receive(c, 14, 70), &handle);
            let FileValue::Count(fd) = finish(work).unwrap() else {
                panic!()
            };
            assert!(v.shared_files().lookup(fd as u32).unwrap().is_ok());
        }
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn zero_attribute_timeout_grants_only_the_completed_check_without_repeated_refresh() {
    let (v, dev) = mounted_local();
    let c = dev.connection().unwrap();
    let work = access(&v, b"/mnt/file", 4);
    let mut a = attributes(1, 0o040755, 0);
    a[..8].fill(0);
    answer(c, &receive(c, 3, 1), &a);
    let work = waiting(work);
    let mut e = lookup_entry(70, 0o100644);
    e[24..32].fill(0);
    answer(c, &receive(c, 1, 1), &e);
    let work = waiting(work);
    let mut a = attributes(170, 0o100644, 0);
    a[..8].fill(0);
    answer(c, &receive(c, 3, 70), &a);
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn protected_hardlink_checks_refreshed_source_modes_and_keeps_the_owner_error_bypass() {
    for (uid, reply_mode, error, ok) in [
        (0u32, 0o100644, 0, false),
        (0, 0o100666, 0, true),
        (0, 0, 5, false),
        (1000, 0, 5, true),
    ] {
        let (v, dev) = mounted_local();
        let c = dev.connection().unwrap();
        let work = waiting(v.path_queries().namespace_work(NamespaceCall::Link {
            follow: false,
            empty_path: false,
            oldfd: AT_FDCWD,
            old: b"/mnt/file".to_vec(),
            newfd: AT_FDCWD,
            new: b"/mnt/alias".to_vec(),
        }));
        answer(c, &receive(c, 3, 1), &attributes(1, 0o040777, 0));
        let work = waiting(work);
        let mut e = lookup_entry(70, 0o100644);
        e[104..108].copy_from_slice(&1u32.to_le_bytes());
        e[108..112].copy_from_slice(&uid.to_le_bytes());
        if uid == 1000 {
            e[24..32].fill(0);
        }
        answer(c, &receive(c, 1, 1), &e);
        let work = waiting(work);
        let absent = receive(c, 1, 1);
        c.write(&reply(id(&absent), -2, &[])).unwrap();
        let work = waiting(work);
        let refresh = receive(c, 3, 70);
        if error == 0 {
            answer(c, &refresh, &attributes(170, reply_mode, uid));
        } else {
            c.write(&reply(id(&refresh), -error, &[])).unwrap();
        }
        let work = if ok {
            let work = waiting(work);
            let request = receive(c, 13, 1);
            let mut e = lookup_entry(70, 0o100666);
            e[104..108].copy_from_slice(&2u32.to_le_bytes());
            answer(c, &request, &e);
            work
        } else {
            work
        };
        let result = finish(work);
        assert!(if ok {
            matches!(result, Ok(FileValue::Count(0)))
        } else {
            matches!(result, Err(Errno(1)))
        });
        receive(c, 2, 70);
        if ok {
            receive(c, 2, 70);
        }
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}
#[test]
fn cross_parent_rename_and_exchange_check_the_moved_directory_write_mode() {
    for exchange in [false, true] {
        let (v, dev) = mounted_local();
        let c = dev.connection().unwrap();
        let work = waiting(v.path_queries().namespace_work(NamespaceCall::Rename {
            oldfd: AT_FDCWD,
            old: b"/mnt/a/dir".to_vec(),
            newfd: AT_FDCWD,
            new: b"/mnt/b/new".to_vec(),
            flags: if exchange { 2 } else { 0 },
        }));
        let work = root(c, work);
        answer(c, &receive(c, 1, 1), &lookup_entry(70, 0o040777));
        let work = waiting(work);
        answer(c, &receive(c, 1, 1), &lookup_entry(80, 0o040777));
        let work = waiting(work);
        let mut source = lookup_entry(71, if exchange { 0o040777 } else { 0o040555 });
        source[108..112].copy_from_slice(&1000u32.to_le_bytes());
        answer(c, &receive(c, 1, 70), &source);
        let work = waiting(work);
        let request = receive(c, 1, 80);
        if exchange {
            let mut target = lookup_entry(81, 0o040555);
            target[108..112].copy_from_slice(&1000u32.to_le_bytes());
            answer(c, &request, &target);
        } else {
            c.write(&reply(id(&request), -2, &[])).unwrap();
        }
        let work = waiting(work);
        let moved = if exchange { 81 } else { 71 };
        answer(
            c,
            &receive(c, 3, moved),
            &attributes(moved + 100, 0o040555, 1000),
        );
        assert!(matches!(finish(work), Err(Errno(13))));
        let mut forgotten = Vec::new();
        for _ in 0..if exchange { 4 } else { 3 } {
            let r = c.read(8192).unwrap();
            assert_eq!(op(&r), 2);
            forgotten.push(u64::from_le_bytes(r[16..24].try_into().unwrap()));
        }
        forgotten.sort_unstable();
        assert_eq!(
            forgotten,
            if exchange {
                vec![70, 71, 80, 81]
            } else {
                vec![70, 71, 80]
            }
        );
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn sticky_create_checks_the_accepted_parent_owner_policy_and_exclusive_order() {
    for (level, parent_mode, owner, caller, flags, error) in [
        (2, 0o041777, 3000u32, 1000, O_CREAT, 13),
        (2, 0o041777, 3000, 0, O_CREAT, 13),
        (2, 0o041777, 3000, 1000, O_CREAT | 0x80, 17),
        (2, 0o041777, 1000, 1000, O_CREAT, 0),
        (2, 0o041777, 2000, 1000, O_CREAT, 0),
        (2, 0o041777, 3000, 1000, 0, 0),
        (0, 0o041777, 3000, 1000, O_CREAT, 0),
        (1, 0o041770, 3000, 1000, O_CREAT, 0),
        (2, 0o041770, 3000, 1000, O_CREAT, 13),
    ] {
        let (mut v, dev) = mounted_local();
        v.credentials = Credentials::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        let policy = v
            .open_at(AT_FDCWD, b"/proc/sys/fs/protected_regular", 1, 0)
            .unwrap();
        v.write(policy, &[b'0' + level]).unwrap();
        v.close(policy).unwrap();
        v.credentials = if caller == 0 {
            Credentials::default()
        } else {
            Credentials::user(caller, 1000)
        };
        let c = dev.connection().unwrap();
        let files = FileEpoch::default().capture(&v, true);
        let paths = v.path_queries();
        assert!(paths
            .open_at_resolve(AT_FDCWD, b"/mnt/file", flags, 0, 0, &files)
            .is_none());
        let work = paths.take_open_work().unwrap();
        let mut a = attributes(1, parent_mode, 2000);
        a[88..92].copy_from_slice(&1000u32.to_le_bytes());
        answer(c, &receive(c, 3, 1), &a);
        let work = waiting(work);
        let mut e = lookup_entry(70, 0o100666);
        e[108..112].copy_from_slice(&owner.to_le_bytes());
        answer(c, &receive(c, 1, 1), &e);
        if error == 0 {
            let work = waiting(work);
            answer(c, &receive(c, 14, 70), &[0; 16]);
            assert!(matches!(finish(work), Ok(FileValue::Count(_))));
        } else {
            assert!(matches!(finish(work), Err(Errno(e)) if e == error));
            receive(c, 2, 70);
        }
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}
