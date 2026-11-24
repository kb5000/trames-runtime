// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
fn read(capacity: u64, name: Option<&[u8]>) -> NamespaceCall {
    NamespaceCall::GetXattr {
        fd: AT_FDCWD,
        path: Some(b"/mnt/file".to_vec()),
        follow: true,
        name: name.map(<[u8]>::to_vec),
        capacity,
    }
}
fn write(value: Option<&[u8]>) -> NamespaceCall {
    NamespaceCall::Xattr {
        fd: AT_FDCWD,
        path: Some(b"/mnt/file".to_vec()),
        follow: true,
        name: b"user.binary".to_vec(),
        value: value.map(<[u8]>::to_vec),
        flags: 1,
    }
}
fn lookup(v: &Vfs, c: &Connection, call: NamespaceCall, mode: u32) -> FileWork {
    let work = waiting(v.path_queries().namespace_work(call));
    answer(c, &receive(c, 1, 1), &entry(70, 230, mode));
    work
}
#[test]
fn get_queries_use_zero_wire_capacity_and_return_a_bounded_count_without_bytes() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let work = waiting(lookup(&v, c, read(0, Some(b"user.size")), 0o100600));
    let request = receive(c, 22, 70);
    assert_eq!(&request[40..48], &[0; 8]);
    assert_eq!(&request[48..], b"user.size\0");
    answer(
        c,
        &request,
        &70000u32
            .to_le_bytes()
            .into_iter()
            .chain([0; 4])
            .collect::<Vec<_>>(),
    );
    assert!(matches!(finish(work), Ok(FileValue::Count(65536))));
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}
#[test]
fn get_clamps_capacity_and_maps_only_full_buffer_erange_to_e2big() {
    for (capacity, expected) in [(2, 34), (70000, 7)] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let work = waiting(lookup(&v, c, read(capacity, Some(b"user.data")), 0o100600));
        let request = receive(c, 22, 70);
        assert_eq!(
            &request[40..44],
            &(capacity.min(65536) as u32).to_le_bytes()
        );
        c.write(&reply(id(&request), -34, &[])).unwrap();
        assert!(matches!(finish(work), Err(Errno(e)) if e == expected));
        receive(c, 2, 70);
    }
}
#[test]
fn lists_require_nonempty_nul_terminated_names_and_preserve_daemon_order() {
    for (bytes, valid) in [
        (b"bad".as_slice(), false),
        (b"\0", false),
        (b"a\0\0", false),
        (b"z\0a\0", true),
        (b"", true),
    ] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let work = waiting(lookup(&v, c, read(32, None), 0o100600));
        let request = receive(c, 23, 70);
        assert_eq!(request.len(), 48);
        answer(c, &request, bytes);
        let result = finish(work);
        if valid {
            assert!(matches!(result, Ok(FileValue::Bytes(v)) if v == bytes));
        } else {
            assert!(matches!(result, Err(Errno(5))));
        }
        receive(c, 2, 70);
    }
}
#[test]
fn set_empty_and_remove_have_different_opcodes_and_hold_original_mount_writers() {
    for value in [Some(b"".as_slice()), None] {
        let (mut v, dev) = mounted();
        let c = dev.connection().unwrap();
        let work = waiting(lookup(&v, c, write(value), 0o100600));
        let request = receive(c, if value.is_some() { 21 } else { 24 }, 70);
        if value.is_some() {
            assert_eq!(&request[40..48], &[0, 0, 0, 0, 1, 0, 0, 0]);
            assert_eq!(&request[48..], b"user.binary\0");
        } else {
            assert_eq!(&request[40..], b"user.binary\0");
        }
        assert_eq!(
            v.mount(None, b"/mnt", None, 4096 | 32 | 1, None),
            Err(Errno(16))
        );
        answer(c, &request, &[]);
        assert!(matches!(finish(work), Ok(FileValue::Count(0))));
        v.mount(None, b"/mnt", None, 4096 | 32 | 1, None).unwrap();
        receive(c, 2, 70);
    }
}
#[test]
fn cancelled_mutation_interrupts_once_releases_writer_and_ignores_a_late_success() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let work = waiting(lookup(&v, c, write(Some(&[0, 255, 7])), 0o100600));
    let request = receive(c, 21, 70);
    assert_eq!(&request[48..], b"user.binary\0\0\xff\x07");
    drop(work);
    let interrupt = receive(c, 36, 0);
    assert_eq!(&interrupt[40..48], &request[8..16]);
    receive(c, 2, 70);
    v.mount(None, b"/mnt", None, 4096 | 32 | 1, None).unwrap();
    answer(c, &request, &[]);
    assert_eq!(c.read(8192), Err(Errno(11)));
}
#[test]
fn enosys_is_cached_for_each_operation_after_ordinary_lookup_and_permissions() {
    for opcode in 21..=24 {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let call = || match opcode {
            21 => write(Some(b"x")),
            24 => write(None),
            22 => read(0, Some(b"user.binary")),
            _ => read(0, None),
        };
        let work = waiting(lookup(&v, c, call(), 0o100600));
        let request = receive(c, opcode, 70);
        c.write(&reply(id(&request), -38, &[])).unwrap();
        assert!(matches!(finish(work), Err(Errno(95))));
        receive(c, 2, 70);
        assert!(matches!(
            finish(lookup(&v, c, call(), 0o100600)),
            Err(Errno(95))
        ));
        receive(c, 2, 70);
        assert_eq!(c.read(8192), Err(Errno(11)));
        let other = if opcode == 22 { 23 } else { 22 };
        let work = waiting(lookup(
            &v,
            c,
            read(
                0,
                if other == 22 {
                    Some(b"user.other")
                } else {
                    None
                },
            ),
            0o100600,
        ));
        answer(c, &receive(c, other, 70), &[0; 8]);
        assert!(matches!(finish(work), Ok(FileValue::Count(0))));
        receive(c, 2, 70);
    }
}
#[test]
fn default_fuse_permissions_delegate_regular_access_but_keep_namespace_rules() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    v.credentials.fsuid = 1000;
    v.credentials.fsgid = 1000;
    v.credentials.caps.effective = 0;
    let work = waiting(lookup(&v, c, read(8, Some(b"user.data")), 0o100600));
    let request = receive(c, 22, 70);
    assert_eq!(&request[24..28], &1000u32.to_le_bytes());
    answer(c, &request, b"data");
    assert!(matches!(finish(work),Ok(FileValue::Bytes(b))if b==b"data"));
    receive(c, 2, 70);
    assert!(matches!(
        finish(lookup(&v, c, read(8, Some(b"trusted.secret")), 0o100600)),
        Err(Errno(61))
    ));
    receive(c, 2, 70);
    assert!(matches!(
        finish(lookup(&v, c, write(Some(b"x")), 0o041777)),
        Err(Errno(1))
    ));
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}
#[test]
fn user_symlink_attributes_are_rejected_without_following_the_symlink() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let mut call = read(8, Some(b"user.data"));
    if let NamespaceCall::GetXattr { follow, .. } = &mut call {
        *follow = false;
    }
    assert!(matches!(
        finish(lookup(&v, c, call, 0o120777)),
        Err(Errno(61))
    ));
    receive(c, 2, 70);
    let mut call = write(Some(b"x"));
    if let NamespaceCall::Xattr { follow, .. } = &mut call {
        *follow = false;
    }
    assert!(matches!(
        finish(lookup(&v, c, call, 0o120777)),
        Err(Errno(1))
    ));
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}
#[test]
fn data_fd_read_keeps_original_inode_after_close_reuse_and_flush() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/file", 0, 0, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    answer(c, &receive(c, 1, 1), &entry(70, 230, 0o100600));
    let work = waiting(work);
    answer(c, &receive(c, 14, 70), &[0; 16]);
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    let work = waiting(paths.namespace_work(NamespaceCall::GetXattr {
        fd: fd as i32,
        path: None,
        follow: true,
        name: Some(b"user.data".to_vec()),
        capacity: 8,
    }));
    let request = receive(c, 22, 70);
    v.shared_files()
        .close_range(fd as u32, fd as u32, 0, 1)
        .unwrap();
    answer(c, &receive(c, 25, 70), &[]);
    assert_eq!(
        v.open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
            .unwrap(),
        fd as u32
    );
    assert_eq!(c.read(8192), Err(Errno(11)));
    answer(c, &request, b"original");
    assert!(matches!(finish(work),Ok(FileValue::Bytes(b))if b==b"original"));
    receive(c, 18, 70);
    receive(c, 2, 70);
}

fn acl_value() -> Vec<u8> {
    [
        2u32,
        1 | (7 << 16),
        u32::MAX,
        4 | (5 << 16),
        u32::MAX,
        32,
        u32::MAX,
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect()
}
fn capabilities() -> Vec<u8> {
    [0x02000001u32, 1, 0, 0, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect()
}
#[test]
fn legacy_acl_reads_fetch_the_full_acl_before_applying_user_capacity() {
    for capacity in [0, 8, 128] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let work = waiting(lookup(&v, c, read(capacity, Some(acl::ACCESS)), 0o100600));
        let request = receive(c, 22, 70);
        assert_eq!(&request[40..44], &4096u32.to_le_bytes());
        answer(c, &request, &acl_value());
        match capacity {
            0 => assert!(matches!(finish(work), Ok(FileValue::Count(28)))),
            8 => assert!(matches!(finish(work), Err(Errno(34)))),
            _ => assert!(matches!(finish(work),Ok(FileValue::Bytes(b))if b==acl_value())),
        }
        receive(c, 2, 70);
    }
}
#[test]
fn acl_sets_ignore_create_flags_and_default_acl_clear_on_regular_files_is_a_noop() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let mut call = write(Some(&acl_value()));
    if let NamespaceCall::Xattr { name, .. } = &mut call {
        *name = acl::ACCESS.to_vec();
    }
    let work = waiting(lookup(&v, c, call, 0o100600));
    let request = receive(c, 21, 70);
    assert_eq!(&request[44..48], &[0; 4]);
    answer(c, &request, &[]);
    finish(work).unwrap();
    receive(c, 2, 70);
    v.credentials.fsuid = 1000;
    v.credentials.caps.effective = 0;
    for value in [None, Some(b"".as_slice())] {
        let mut call = write(value);
        if let NamespaceCall::Xattr { name, .. } = &mut call {
            *name = acl::DEFAULT.to_vec();
        }
        assert!(matches!(
            finish(lookup(&v, c, call, 0o100600)),
            Ok(FileValue::Count(0))
        ));
        receive(c, 2, 70);
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
    let mut call = write(Some(&acl_value()));
    if let NamespaceCall::Xattr { name, .. } = &mut call {
        *name = acl::ACCESS.to_vec();
    }
    assert!(matches!(
        finish(lookup(&v, c, call, 0o100600)),
        Err(Errno(1))
    ));
    receive(c, 2, 70);
}
#[test]
fn capability_reads_query_then_fetch_before_returning_length_or_data() {
    for capacity in [0, 8, 128] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let work = waiting(lookup(
            &v,
            c,
            read(capacity, Some(file_caps::NAME)),
            0o100600,
        ));
        let request = receive(c, 22, 70);
        assert_eq!(&request[40..44], &[0; 4]);
        answer(c, &request, &[20, 0, 0, 0, 0, 0, 0, 0]);
        let work = waiting(work);
        let request = receive(c, 22, 70);
        assert_eq!(&request[40..44], &20u32.to_le_bytes());
        answer(c, &request, &capabilities());
        match capacity {
            0 => assert!(matches!(finish(work), Ok(FileValue::Count(20)))),
            8 => assert!(matches!(finish(work), Err(Errno(34)))),
            _ => assert!(matches!(finish(work),Ok(FileValue::Bytes(b))if b==capabilities())),
        }
        receive(c, 2, 70);
    }
}
#[test]
fn malformed_capability_set_is_rejected_before_sending_the_daemon_mutation() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let mut call = write(Some(b"bad"));
    if let NamespaceCall::Xattr { name, .. } = &mut call {
        *name = file_caps::NAME.to_vec();
    }
    assert!(matches!(
        finish(lookup(&v, c, call, 0o100600)),
        Err(Errno(22))
    ));
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}
#[test]
fn chown_clears_capabilities_on_original_inode_and_propagates_remove_denial() {
    for denied in [false, true] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let call = NamespaceCall::Chown {
            fd: AT_FDCWD,
            path: Some(b"/mnt/file".to_vec()),
            uid: 1,
            gid: 1,
            nofollow: false,
            empty: false,
        };
        let work = waiting(lookup(&v, c, call, 0o106755));
        let cap = receive(c, 22, 70);
        assert_eq!(&cap[48..], b"security.capability\0");
        answer(c, &cap, &[20, 0, 0, 0, 0, 0, 0, 0]);
        let work = waiting(work);
        let remove = receive(c, 24, 70);
        assert_eq!(&remove[40..], b"security.capability\0");
        if denied {
            c.write(&reply(id(&remove), -1, &[])).unwrap();
            assert!(matches!(finish(work), Err(Errno(1))));
        } else {
            answer(c, &remove, &[]);
            let work = waiting(work);
            let mut attr = [0; 104];
            attr[16..].copy_from_slice(&entry(70, 230, 0o106755)[40..]);
            answer(c, &receive(c, 3, 70), &attr);
            let work = waiting(work);
            let set = receive(c, 4, 70);
            assert_eq!(&set[108..112], &0o100755u32.to_le_bytes());
            attr[76..80].copy_from_slice(&0o100755u32.to_le_bytes());
            answer(c, &set, &attr);
            assert!(matches!(finish(work), Ok(FileValue::Count(0))));
        }
        receive(c, 2, 70);
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}
