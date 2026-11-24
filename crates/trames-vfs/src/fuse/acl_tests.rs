// SPDX-License-Identifier: GPL-3.0-or-later
use super::permission_tests::{attributes, lookup_entry};
use super::*;
const OPTIONS: u32 = (1 << 20) | (1 << 6) | (1 << 29);
fn mounted_acl() -> (Vfs, Arc<Device>) {
    let (mut v, d) = mount_vfs_negotiated(Vfs::default(), 0, ",allow_other", OPTIONS);
    v.credentials = Credentials::user(1000, 1000);
    (v, d)
}
fn acl(perm: u16) -> Vec<u8> {
    let mut b = 2u32.to_le_bytes().to_vec();
    for (tag, p, id) in [
        (1u16, 0, u32::MAX),
        (2, perm, 1000),
        (4, 0, u32::MAX),
        (16, 4, u32::MAX),
        (32, 4, u32::MAX),
    ] {
        b.extend(tag.to_le_bytes());
        b.extend(p.to_le_bytes());
        b.extend(id.to_le_bytes());
    }
    b
}
fn root(c: &Connection, work: FileWork) -> FileWork {
    answer(c, &receive(c, 3, 1), &attributes(1, 0o040755, 0));
    let work = waiting(work);
    let q = receive(c, 22, 1);
    assert_eq!(&q[40..44], &4096u32.to_le_bytes());
    c.write(&reply(id(&q), -61, &[])).unwrap();
    waiting(work)
}
fn root_again(c: &Connection, work: FileWork) -> FileWork {
    let q = receive(c, 22, 1);
    c.write(&reply(id(&q), -61, &[])).unwrap();
    waiting(work)
}
fn open(v: &Vfs) -> FileWork {
    let files = FileEpoch::default().capture(v, true);
    let paths = v.path_queries();
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/file", 0, 0, 0, &files)
        .is_none());
    paths.take_open_work().unwrap()
}
fn granted(v: &Vfs, c: &Connection) -> u32 {
    let work = root(c, open(v));
    answer(c, &receive(c, 1, 1), &lookup_entry(70, 0o100040));
    let work = waiting(work);
    answer(c, &receive(c, 22, 70), &acl(4));
    let work = waiting(work);
    answer(c, &receive(c, 14, 70), &[0; 16]);
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    fd as u32
}
#[test]
fn negotiated_acl_implies_local_checks_and_named_denial_does_not_fall_through_to_other() {
    for (perm, ok) in [(4, true), (0, false)] {
        let (v, d) = mounted_acl();
        let c = d.connection().unwrap();
        let work = root(c, open(&v));
        answer(c, &receive(c, 1, 1), &lookup_entry(70, 0o100044));
        let work = waiting(work);
        let q = receive(c, 22, 70);
        assert_eq!(&q[48..], b"system.posix_acl_access\0");
        answer(c, &q, &acl(perm));
        let work = waiting(work);
        if ok {
            answer(c, &receive(c, 14, 70), &[0; 16]);
            assert!(matches!(finish(work), Ok(FileValue::Count(_))));
        } else {
            answer(c, &receive(c, 3, 70), &attributes(170, 0o100044, 0));
            let work = waiting(work);
            answer(c, &receive(c, 22, 70), &acl(0));
            assert!(matches!(finish(work), Err(Errno(13))));
            receive(c, 2, 70);
        }
    }
}
#[test]
fn cached_inode_acl_survives_lookup_and_a_failed_acl_set_invalidates_it() {
    let (mut v, d) = mounted_acl();
    let c = d.connection().unwrap();
    let fd = granted(&v, c);
    let paths = v.path_queries();
    assert!(paths
        .access_at(AT_FDCWD, b"/mnt/file", 4, true, false)
        .is_none());
    let work = root_again(c, paths.take_fuse_stat().unwrap());
    answer(c, &receive(c, 1, 1), &lookup_entry(70, 0o100040));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
    v.credentials = Credentials::default();
    let work = waiting(v.path_queries().namespace_work(NamespaceCall::Xattr {
        fd: fd as i32,
        path: None,
        follow: true,
        name: crate::acl::ACCESS.to_vec(),
        value: Some(acl(0)),
        flags: 1,
    }));
    let q = receive(c, 21, 70);
    assert_eq!(&q[44..56], &[0; 12]);
    assert_eq!(&q[56..80], b"system.posix_acl_access\0");
    c.write(&reply(id(&q), -1, &[])).unwrap();
    assert!(matches!(finish(work), Err(Errno(1))));
    v.credentials = Credentials::user(1000, 1000);
    let work = root_again(c, open(&v));
    answer(c, &receive(c, 1, 1), &lookup_entry(70, 0o100040));
    let work = waiting(work);
    let old_acl = receive(c, 22, 70);
    v.credentials = Credentials::default();
    let setter = waiting(v.path_queries().namespace_work(NamespaceCall::Xattr {
        fd: fd as i32,
        path: None,
        follow: true,
        name: crate::acl::ACCESS.to_vec(),
        value: Some(acl(0)),
        flags: 0,
    }));
    let request = receive(c, 21, 70);
    c.write(&reply(id(&request), -1, &[])).unwrap();
    assert!(matches!(finish(setter), Err(Errno(1))));
    answer(c, &old_acl, &acl(4));
    let work = waiting(work);
    answer(c, &receive(c, 3, 70), &attributes(170, 0o100040, 0));
    let work = waiting(work);
    // The old successful read cannot bypass the new observation after refresh.
    answer(c, &receive(c, 22, 70), &acl(0));
    assert!(matches!(finish(work), Err(Errno(13))));
    receive(c, 2, 70);
}
#[test]
fn acl_query_errors_and_cancellation_keep_the_original_lookup_lifetime() {
    for error in [34, 95, 5, 4] {
        let (v, d) = mounted_acl();
        let c = d.connection().unwrap();
        let work = root(c, open(&v));
        answer(c, &receive(c, 1, 1), &lookup_entry(70, 0o100040));
        let work = waiting(work);
        let q = receive(c, 22, 70);
        if error == 4 {
            drop(work);
            answer(c, &receive(c, 36, 0), &[]);
            receive(c, 2, 70);
            answer(c, &q, &acl(4));
        } else {
            c.write(&reply(id(&q), -error, &[])).unwrap();
            assert!(matches!(finish(work),Err(Errno(e))if e==if error==34{7}else{error as u32}));
            receive(c, 2, 70);
        }
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn delayed_init_rechecks_negotiated_permissions_with_the_original_open_intent() {
    for cancel in [false, true] {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        v.mkdir_at(AT_FDCWD, b"/mnt", 0o755).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/dev/fuse", 2, 0).unwrap();
        let dev = v.fuse_device(fd).unwrap().unwrap();
        let options = format!("fd={fd},rootmode=40755,user_id=0,group_id=0,allow_other");
        v.mount(None, b"/mnt", Some(b"fuse"), 0, Some(options.as_bytes()))
            .unwrap();
        v.credentials = Credentials::user(1000, 1000);
        let c = dev.connection().unwrap();
        let work = waiting(open(&v));
        let init = receive(c, 26, 0);
        assert_eq!(
            u32::from_le_bytes(init[52..56].try_into().unwrap()) & OPTIONS,
            OPTIONS
        );
        v.credentials = Credentials::default();
        let work = if cancel {
            drop(work);
            None
        } else {
            Some(work)
        };
        let mut out = [0; 64];
        out[..4].copy_from_slice(&7u32.to_le_bytes());
        out[4..8].copy_from_slice(&31u32.to_le_bytes());
        out[12..16].copy_from_slice(&OPTIONS.to_le_bytes());
        answer(c, &init, &out);
        if cancel {
            assert_eq!(c.read(8192), Err(Errno(11)));
            continue;
        }
        let work = root(c, waiting(work.unwrap()));
        answer(c, &receive(c, 1, 1), &lookup_entry(70, 0o100040));
        let work = waiting(work);
        let q = receive(c, 22, 70);
        assert_eq!(&q[24..28], &1000u32.to_le_bytes());
        answer(c, &q, &acl(4));
        let work = waiting(work);
        answer(c, &receive(c, 14, 70), &[0; 16]);
        assert!(matches!(finish(work), Ok(FileValue::Count(_))));
    }
}

#[test]
fn root_acl_is_requeried_and_a_permission_refresh_discards_its_old_reply() {
    let (v, d) = mounted_acl();
    let c = d.connection().unwrap();
    let _fd = granted(&v, c);
    let work = open(&v);
    answer(c, &receive(c, 22, 1), &acl(0));
    let work = waiting(work);
    answer(c, &receive(c, 3, 1), &attributes(1, 0o040755, 0));
    let work = waiting(work);
    answer(c, &receive(c, 22, 1), &acl(0));
    assert!(matches!(finish(work), Err(Errno(13))));
    assert_eq!(c.read(8192), Err(Errno(11)));
}

fn get_acl(v: &Vfs, fd: u32, name: &[u8], capacity: u64) -> FileWork {
    v.path_queries().namespace_work(NamespaceCall::GetXattr {
        fd: fd as i32,
        path: None,
        follow: true,
        name: Some(name.to_vec()),
        capacity,
    })
}
#[test]
fn public_acl_reads_share_permission_and_default_caches_with_original_capacity() {
    for negative in [false, true] {
        let (v, d) = mounted_acl();
        let c = d.connection().unwrap();
        let fd = granted(&v, c);
        assert!(matches!(
            finish(waiting(get_acl(&v, fd, crate::acl::ACCESS, 0))),
            Ok(FileValue::Count(44))
        ));
        assert!(matches!(
            finish(waiting(get_acl(&v, fd, crate::acl::ACCESS, 1))),
            Err(Errno(34))
        ));
        assert_eq!(c.read(8192), Err(Errno(11)));
        let work = waiting(get_acl(&v, fd, crate::acl::DEFAULT, 0));
        let q = receive(c, 22, 70);
        assert_eq!(&q[48..], b"system.posix_acl_default\0");
        if negative {
            c.write(&reply(id(&q), -61, &[])).unwrap();
            assert!(matches!(finish(work), Err(Errno(61))));
            assert!(matches!(
                finish(waiting(get_acl(&v, fd, crate::acl::DEFAULT, 65536))),
                Err(Errno(61))
            ));
        } else {
            answer(c, &q, &acl(4));
            assert!(matches!(finish(work), Ok(FileValue::Count(44))));
            assert!(
                matches!(finish(waiting(get_acl(&v, fd, crate::acl::DEFAULT, 65536))), Ok(FileValue::Bytes(b)) if b == acl(4))
            );
        }
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}
#[test]
fn late_public_acl_read_returns_its_observation_without_repopulating_invalidated_cache() {
    let (mut v, d) = mounted_acl();
    let c = d.connection().unwrap();
    let fd = granted(&v, c);
    let work = waiting(get_acl(&v, fd, crate::acl::DEFAULT, 65536));
    let old = receive(c, 22, 70);
    v.credentials = Credentials::default();
    let setter = waiting(v.path_queries().namespace_work(NamespaceCall::Xattr {
        fd: fd as i32,
        path: None,
        follow: true,
        name: crate::acl::ACCESS.to_vec(),
        value: Some(acl(0)),
        flags: 0,
    }));
    c.write(&reply(id(&receive(c, 21, 70)), -1, &[])).unwrap();
    assert!(matches!(finish(setter), Err(Errno(1))));
    answer(c, &old, &acl(4));
    assert!(matches!(finish(work), Ok(FileValue::Bytes(b)) if b == acl(4)));
    for name in [crate::acl::ACCESS, crate::acl::DEFAULT] {
        let work = waiting(get_acl(&v, fd, name, 65536));
        answer(c, &receive(c, 22, 70), &acl(0));
        assert!(matches!(finish(work), Ok(FileValue::Bytes(b)) if b == acl(0)));
    }
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn overlapping_public_reads_preserve_first_fill_for_both_completion_orders() {
    for reverse in [false, true] {
        let (v, d) = mounted_acl();
        let c = d.connection().unwrap();
        let fd = granted(&v, c);
        let first = waiting(get_acl(&v, fd, crate::acl::DEFAULT, 65536));
        let a = receive(c, 22, 70);
        let second = waiting(get_acl(&v, fd, crate::acl::DEFAULT, 65536));
        let b = receive(c, 22, 70);
        if reverse {
            answer(c, &b, &acl(6));
            assert!(matches!(finish(second), Ok(FileValue::Bytes(v)) if v == acl(6)));
            answer(c, &a, &acl(4));
            assert!(matches!(finish(first), Ok(FileValue::Bytes(v)) if v == acl(4)));
        } else {
            answer(c, &a, &acl(4));
            assert!(matches!(finish(first), Ok(FileValue::Bytes(v)) if v == acl(4)));
            answer(c, &b, &acl(6));
            assert!(matches!(finish(second), Ok(FileValue::Bytes(v)) if v == acl(6)));
        }
        assert!(
            matches!(finish(waiting(get_acl(&v, fd, crate::acl::DEFAULT, 65536))), Ok(FileValue::Bytes(v)) if v == acl(4))
        );
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn failed_owner_and_cancelled_old_follower_leave_a_replacement_fill_owned() {
    let (v, d) = mounted_acl();
    let c = d.connection().unwrap();
    let fd = granted(&v, c);
    let first = waiting(get_acl(&v, fd, crate::acl::DEFAULT, 65536));
    let a = receive(c, 22, 70);
    let old = waiting(get_acl(&v, fd, crate::acl::DEFAULT, 65536));
    let b = receive(c, 22, 70);
    c.write(&reply(id(&a), -5, &[])).unwrap();
    assert!(matches!(finish(first), Err(Errno(5))));
    let replacement = waiting(get_acl(&v, fd, crate::acl::DEFAULT, 65536));
    let q = receive(c, 22, 70);
    drop(old);
    answer(c, &receive(c, 36, 0), &[]);
    answer(c, &b, &acl(6));
    let follower = waiting(get_acl(&v, fd, crate::acl::DEFAULT, 65536));
    let f = receive(c, 22, 70);
    answer(c, &q, &acl(2));
    assert!(matches!(finish(replacement), Ok(FileValue::Bytes(v)) if v == acl(2)));
    answer(c, &f, &acl(4));
    assert!(matches!(finish(follower), Ok(FileValue::Bytes(v)) if v == acl(4)));
    assert!(
        matches!(finish(waiting(get_acl(&v, fd, crate::acl::DEFAULT, 65536))), Ok(FileValue::Bytes(v)) if v == acl(2))
    );
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn cancelled_owner_allows_new_fill_without_promoting_an_already_pending_follower() {
    let (v, d) = mounted_acl();
    let c = d.connection().unwrap();
    let fd = granted(&v, c);
    let first = waiting(get_acl(&v, fd, crate::acl::DEFAULT, 65536));
    let a = receive(c, 22, 70);
    let old = waiting(get_acl(&v, fd, crate::acl::DEFAULT, 65536));
    let b = receive(c, 22, 70);
    drop(first);
    answer(c, &receive(c, 36, 0), &[]);
    let replacement = waiting(get_acl(&v, fd, crate::acl::DEFAULT, 65536));
    let q = receive(c, 22, 70);
    answer(c, &b, &acl(6));
    assert!(matches!(finish(old), Ok(FileValue::Bytes(v)) if v == acl(6)));
    let follower = waiting(get_acl(&v, fd, crate::acl::DEFAULT, 65536));
    let f = receive(c, 22, 70);
    answer(c, &a, &acl(4));
    answer(c, &q, &acl(2));
    assert!(matches!(finish(replacement), Ok(FileValue::Bytes(v)) if v == acl(2)));
    answer(c, &f, &acl(4));
    assert!(matches!(finish(follower), Ok(FileValue::Bytes(v)) if v == acl(4)));
    assert!(
        matches!(finish(waiting(get_acl(&v, fd, crate::acl::DEFAULT, 65536))), Ok(FileValue::Bytes(v)) if v == acl(2))
    );
    assert_eq!(c.read(8192), Err(Errno(11)));
}
