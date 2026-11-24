// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

#[test]
fn statfs_retains_accepted_inode_and_reads_live_flags_after_reply() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Statfs {
        fd: AT_FDCWD,
        path: Some(b"/mnt/file".to_vec()),
    }));
    answer(c, &receive(c, 1, 1), &entry(70, 230, 0o100644));
    let work = waiting(work);
    let request = receive(c, 17, 70);
    v.mount(None, b"/mnt", None, 4096 | 32 | 1, None).unwrap();
    let mut bytes = [0; 80];
    bytes[..8].copy_from_slice(&123u64.to_le_bytes());
    bytes[40..44].copy_from_slice(&8192u32.to_le_bytes());
    answer(c, &request, &bytes);
    let FileValue::Bytes(out) = finish(work).unwrap() else {
        panic!()
    };
    assert_eq!(out.len(), 120);
    assert_eq!(&out[16..24], &123u64.to_le_bytes());
    assert_eq!(&out[8..16], &8192u64.to_le_bytes());
    assert_eq!(u64::from_le_bytes(out[80..88].try_into().unwrap()) & 33, 33);
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn descriptor_statfs_uses_original_detached_inode_after_close_and_fd_reuse() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/file", O_PATH, 0, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    answer(c, &receive(c, 1, 1), &entry(70, 230, 0o100644));
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    let work = waiting(paths.namespace_work(NamespaceCall::Statfs {
        fd: fd as i32,
        path: None,
    }));
    let request = receive(c, 17, 70);
    v.shared_files()
        .close_range(fd as u32, fd as u32, 0, 1)
        .unwrap();
    assert_eq!(
        v.open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
            .unwrap(),
        fd as u32
    );
    v.umount(b"/mnt", 2).unwrap();
    answer(c, &request, &[0; 80]);
    let FileValue::Bytes(bytes) = finish(work).unwrap() else {
        panic!()
    };
    assert_eq!(&bytes[..8], &0x65735546u64.to_le_bytes());
    // The retained query may still project the original descriptor metadata.
    drop(paths);
    assert_eq!(
        c.read(8192),
        Err(Errno(19)),
        "last real use closes the connection"
    );
}

#[test]
fn statfs_cancellation_and_bad_replies_release_the_lookup_without_path_replay() {
    for malformed in [false, true] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        let work = waiting(paths.namespace_work(NamespaceCall::Statfs {
            fd: AT_FDCWD,
            path: Some(b"/mnt/file".to_vec()),
        }));
        answer(c, &receive(c, 1, 1), &entry(70, 230, 0o100644));
        let work = waiting(work);
        let request = receive(c, 17, 70);
        if malformed {
            assert_eq!(c.write(&reply(id(&request), 0, &[0; 79])), Err(Errno(22)));
            assert!(matches!(finish(work), Err(Errno(5))));
        } else {
            drop(work);
            let interrupt = receive(c, 36, 0);
            assert_eq!(&interrupt[40..48], &request[8..16]);
            answer(c, &request, &[0; 80]);
        }
        receive(c, 2, 70);
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}
