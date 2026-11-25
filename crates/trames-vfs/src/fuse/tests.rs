// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
#[path = "access_tests.rs"]
mod access_tests;
#[path = "acl_tests.rs"]
mod acl_tests;
#[path = "attribute_tests.rs"]
mod attribute_tests;
#[path = "create_tests.rs"]
mod create_tests;
#[path = "data_tests.rs"]
mod data_tests;
#[path = "directory_tests.rs"]
mod directory_tests;
#[path = "entry_reply_tests.rs"]
mod entry_reply_tests;
#[path = "file_bind_tests.rs"]
mod file_bind_tests;
#[path = "link_tests.rs"]
mod link_tests;
#[path = "mount_fd_tests.rs"]
mod mount_fd_tests;
#[path = "namespace_tests.rs"]
mod namespace_tests;
#[cfg(all(feature = "hostfs", unix))]
#[path = "native_walk_tests.rs"]
mod native_walk_tests;
#[path = "parent_tests.rs"]
mod parent_tests;
#[path = "permission_tests.rs"]
mod permission_tests;
#[path = "proc_walk_tests.rs"]
mod proc_walk_tests;
#[path = "retry_tests.rs"]
mod retry_tests;
#[path = "statfs_tests.rs"]
mod statfs_tests;
#[path = "symlink_inode_tests.rs"]
mod symlink_inode_tests;
#[path = "topology_tests.rs"]
mod topology_tests;
#[path = "transfer_tests.rs"]
mod transfer_tests;
#[path = "walk_tests.rs"]
mod walk_tests;
#[path = "xattr_tests.rs"]
mod xattr_tests;

pub(super) fn reply(id: u64, error: i32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(((16 + payload.len()) as u32).to_le_bytes());
    bytes.extend(error.to_le_bytes());
    bytes.extend(id.to_le_bytes());
    bytes.extend(payload);
    bytes
}
pub(super) fn id(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[8..16].try_into().unwrap())
}
fn op(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[4..8].try_into().unwrap())
}
fn start() -> (Arc<Device>, Arc<Connection>) {
    let dev = Device::new(UserNamespace::default());
    let c = dev.connect(Caller::default()).unwrap();
    let init = c.read(8192).unwrap();
    assert_eq!(op(&init), 26);
    let mut payload = [0; 64];
    payload[..4].copy_from_slice(&7u32.to_le_bytes());
    payload[4..8].copy_from_slice(&31u32.to_le_bytes());
    let out = reply(id(&init), 0, &payload);
    assert_eq!(c.write(&out), Ok(out.len()));
    (dev, c)
}
#[test]
fn handshake_gates_queued_requests_and_preserves_header_identity() {
    let c = Connection::new(Caller::default());
    let caller = Caller {
        uid: 11,
        gid: 12,
        pid: 42,
    };
    let req = c.request(3, 1, caller, &[0; 16]).unwrap();
    assert_eq!(c.read(100), Err(Errno(22)));
    let init = c.read(8192).unwrap();
    assert_eq!(c.read(8192), Err(Errno(11)));
    assert_eq!(c.poll(1).0, 0);
    assert_eq!(c.write(&[0; 15]), Err(Errno(22)));
    let mut info = [0; 64];
    info[..4].copy_from_slice(&7u32.to_le_bytes());
    info[4..8].copy_from_slice(&31u32.to_le_bytes());
    c.write(&reply(id(&init), 0, &info)).unwrap();
    assert_eq!(c.poll(1).0, 1);
    let msg = c.read(8192).unwrap();
    assert_eq!(op(&msg), 3);
    assert_eq!(msg.len(), 56);
    assert_eq!(&msg[24..28], &11u32.to_le_bytes());
    assert_eq!(&msg[28..32], &12u32.to_le_bytes());
    assert_eq!(&msg[32..36], &42u32.to_le_bytes());
    let stat = [0; 104];
    c.write(&reply(id(&msg), 0, &stat)).unwrap();
    assert_eq!(req.take(), Some(Ok(stat.to_vec())));
    assert_eq!(c.write(&reply(id(&msg), 0, b"twice")), Err(Errno(2)));
}
#[test]
fn malformed_reply_retires_the_original_request_with_io_error() {
    for length in [0, 103, 105] {
        let (_dev, c) = start();
        let req = c.request(3, 1, Caller::default(), &[0; 16]).unwrap();
        let message = receive(&c, 3, 1);
        assert_eq!(
            c.write(&reply(id(&message), 0, &vec![0; length])),
            Err(Errno(22))
        );
        assert_eq!(req.take(), Some(Err(Errno(5))));
        assert_eq!(c.write(&reply(id(&message), 0, &[0; 104])), Err(Errno(2)));
    }
    let (_dev, c) = start();
    let req = c.request(14, 5, Caller::default(), &[0; 8]).unwrap();
    let message = receive(&c, 14, 5);
    assert_eq!(c.write(&reply(id(&message), -38, &[0])), Err(Errno(22)));
    assert_eq!(req.take(), Some(Err(Errno(5))));
    drop(req);
    assert_eq!(c.read(8192), Err(Errno(11)));
}
#[test]
fn init_short_payload_is_zero_extended_and_oversized_payload_ends_the_connection() {
    for size in [0, 7, 8, 64, 65] {
        let c = Connection::new(Caller::default());
        let message = c.read(8192).unwrap();
        let mut payload = vec![0; size];
        if size >= 8 {
            payload[..4].copy_from_slice(&7u32.to_le_bytes());
            payload[4..8].copy_from_slice(&31u32.to_le_bytes());
        }
        let result = c.write(&reply(id(&message), 0, &payload));
        if size == 65 {
            assert_eq!(result, Err(Errno(22)));
        } else {
            assert_eq!(result, Ok(16 + size));
        }
        assert_eq!(c.init_result().is_ok(), matches!(size, 8 | 64));
    }
}
#[test]
fn interrupt_priority_retry_disable_and_reply_races() {
    let (_dev, c) = start();
    let a = c.request(3, 1, Caller::default(), &[]).unwrap();
    let b = c.request(10, 1, Caller::default(), &[]).unwrap();
    a.interrupt();
    a.interrupt();
    let first = c.read(8192).unwrap();
    assert_eq!(op(&first), 3);
    let n = id(&first);
    let interrupt = c.read(8192).unwrap();
    assert_eq!(op(&interrupt), 36);
    assert_eq!(id(&interrupt), n | 1);
    assert_eq!(&interrupt[40..], &n.to_le_bytes());
    assert_eq!(c.write(&reply(n | 1, 0, &[0; 8])), Err(Errno(22)));
    c.write(&reply(n | 1, -11, &[])).unwrap();
    assert_eq!(id(&c.read(8192).unwrap()), n | 1);
    c.write(&reply(n | 1, -38, &[])).unwrap();
    assert!(a.take().is_none());
    c.write(&reply(n, -4, &[])).unwrap();
    assert_eq!(a.take(), Some(Err(Errno(4))));
    let next = c.read(8192).unwrap();
    assert_eq!(op(&next), 10);
    b.interrupt();
    assert_eq!(c.read(8192), Err(Errno(11)));
    c.write(&reply(id(&next), 0, &[])).unwrap();
    assert_eq!(b.take(), Some(Ok(vec![])));
}
#[test]
fn unread_cancel_sent_cancel_and_last_daemon_close() {
    let (dev, c) = start();
    let peer = Device::new(UserNamespace::default());
    peer.attach_clone(&dev).unwrap();
    assert_eq!(dev.attach_clone(&peer), Err(Errno(22)));
    let mk = || c.request(10, 1, Caller::default(), &[]).unwrap();
    drop(mk());
    assert_eq!(c.read(8192), Err(Errno(11)));
    let sent = mk();
    let n = id(&c.read(8192).unwrap());
    drop(sent);
    c.write(&reply(n, 0, &[])).unwrap();
    let in_flight = mk();
    c.read(8192).unwrap();
    let queued = mk();
    drop(dev);
    assert!(in_flight.take().is_none());
    drop(peer);
    assert_eq!(in_flight.take(), Some(Err(Errno(103))));
    assert_eq!(queued.take(), Some(Err(Errno(103))));
    assert_eq!(c.poll(1).0, 8);
    assert_eq!(c.read(8192), Err(Errno(19)));
}

#[test]
fn idle_daemon_disconnect_invalidates_the_observed_poll_state() {
    struct Wake;
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    let (device, connection) = start();
    assert_eq!(connection.read(8192), Err(Errno(11)));
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let signal = IoSignal::new(0, Arc::downgrade(&wake));
    let _registered = device.subscribe(&signal);
    let before = device.poll(1);
    assert_eq!(before.0, 0);
    connection.abort();
    assert!(signal.ready());
    let after = device.poll(1);
    assert_eq!(after.0, 8);
    assert_ne!(after.1, before.1);
    assert_eq!(connection.read(8192), Err(Errno(19)));
    signal.reset();
    connection.abort();
    assert_eq!(device.poll(1), after);
    assert!(!signal.ready());
}

#[test]
fn waiter_registered_before_mount_observes_successive_requests() {
    struct Wake;
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let signal = IoSignal::new(0, Arc::downgrade(&wake));
    let device = Device::new(UserNamespace::default());
    let _registered = device.subscribe(&signal);
    let connection = device.connect(Caller::default()).unwrap();
    let init = connection.read(8192).unwrap();
    let mut info = [0; 64];
    info[..4].copy_from_slice(&7u32.to_le_bytes());
    info[4..8].copy_from_slice(&31u32.to_le_bytes());
    connection.write(&reply(id(&init), 0, &info)).unwrap();
    for _ in 0..3 {
        signal.reset();
        let request = connection.request(10, 1, Caller::default(), &[]).unwrap();
        assert!(signal.ready());
        let msg = connection.read(8192).unwrap();
        connection.write(&reply(id(&msg), 0, &[])).unwrap();
        assert_eq!(request.take(), Some(Ok(vec![])));
    }
}

pub(super) fn mounted() -> (Vfs, Arc<Device>) {
    mounted_with_limit(0)
}
pub(super) fn mounted_with_limit(max_write: u32) -> (Vfs, Arc<Device>) {
    mount_vfs(Vfs::default(), max_write)
}
fn mount_vfs(v: Vfs, max_write: u32) -> (Vfs, Arc<Device>) {
    mount_vfs_options(v, max_write, "")
}
fn mount_vfs_options(v: Vfs, max_write: u32, extra: &str) -> (Vfs, Arc<Device>) {
    mount_vfs_negotiated(v, max_write, extra, 0)
}
pub(super) fn mount_vfs_negotiated(
    mut v: Vfs,
    max_write: u32,
    extra: &str,
    flags: u32,
) -> (Vfs, Arc<Device>) {
    v.set_runtime_info(1, RuntimeInfo::default());
    v.mkdir_at(AT_FDCWD, b"/mnt", 0o755).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/dev/fuse", 2, 0).unwrap();
    let device = v.fuse_device(fd).unwrap().unwrap();
    let opts = format!("fd={fd},rootmode=40755,user_id=0,group_id=0{extra}");
    v.mount(None, b"/mnt", Some(b"fuse"), 0, Some(opts.as_bytes()))
        .unwrap();
    let c = device.connection().unwrap();
    let init = c.read(8192).unwrap();
    let mut version = [0; 64];
    version[..4].copy_from_slice(&7u32.to_le_bytes());
    let minor = if flags & (1 << 29) != 0 { 34u32 } else { 31u32 };
    version[4..8].copy_from_slice(&minor.to_le_bytes());
    version[20..24].copy_from_slice(&max_write.to_le_bytes());
    version[12..16].copy_from_slice(&flags.to_le_bytes());
    c.write(&reply(id(&init), 0, &version)).unwrap();
    (v, device)
}

pub(super) fn entry(node: u64, ino: u64, mode: u32) -> [u8; 128] {
    let mut entry = [0; 128];
    entry[..8].copy_from_slice(&node.to_le_bytes());
    entry[24..32].copy_from_slice(&1u64.to_le_bytes());
    entry[40..48].copy_from_slice(&ino.to_le_bytes());
    entry[100..104].copy_from_slice(&mode.to_le_bytes());
    entry
}
pub(super) fn receive(c: &Connection, opcode: u32, node: u64) -> Vec<u8> {
    let bytes = c.read(8192).unwrap();
    assert_eq!(op(&bytes), opcode);
    assert_eq!(u64::from_le_bytes(bytes[16..24].try_into().unwrap()), node);
    bytes
}
pub(super) fn answer(c: &Connection, req: &[u8], body: &[u8]) {
    c.write(&reply(id(req), 0, body)).unwrap();
}
fn forget_each(c: &Connection, expected: &[u64]) {
    let mut observed = Vec::new();
    for _ in expected {
        let forget = c.read(8192).unwrap();
        assert_eq!(op(&forget), 2);
        assert_eq!(&forget[40..], &1u64.to_le_bytes());
        observed.push(u64::from_le_bytes(forget[16..24].try_into().unwrap()));
        assert_eq!(c.write(&reply(id(&forget), 0, &[])), Err(Errno(2)));
    }
    observed.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(observed, expected);
}
#[track_caller]
pub(super) fn waiting(work: FileWork) -> FileWork {
    match work.run() {
        FileOutcome::Waiting(work) => work,
        FileOutcome::Complete(reply) => panic!(
            "next daemon operation completed, error: {:?}",
            reply.result.err()
        ),
        FileOutcome::Owner(_) => panic!("next daemon operation requires owner metadata"),
        FileOutcome::Layout(_) => panic!("next daemon operation requires layout admission"),
    }
}
pub(super) fn finish(work: FileWork) -> Result<FileValue> {
    match work.run() {
        FileOutcome::Complete(reply) => reply.result,
        _ => panic!("expected completed operation"),
    }
}

#[test]
fn nested_lookup_stat_returns_ino_and_forgets_each_reference() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    assert!(paths.statx_at(AT_FDCWD, b"/mnt/a/b", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    let a = receive(c, 1, 1);
    assert_eq!(&a[40..], b"a\0");
    answer(c, &a, &entry(22, 102, 0o40755));
    let work = waiting(work);
    let b = receive(c, 1, 22);
    assert_eq!(&b[40..], b"b\0");
    answer(c, &b, &entry(23, 103, 0o100644));
    let FileValue::FuseStat(stat, m) = finish(work).unwrap() else {
        panic!()
    };
    assert!(!m.is_root);
    assert_eq!(u64::from_le_bytes(stat[8..16].try_into().unwrap()), 103);
    forget_each(c, &[22, 23]);
}

#[test]
fn zero_ttl_refreshes_by_node_and_readlink_uses_daemon_target() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    assert!(paths.statx_at(AT_FDCWD, b"/mnt/link", true).is_none());
    let work = paths.take_fuse_stat().unwrap();
    let mut found = entry(14, 1004, 0o120777);
    found[24..32].fill(0);
    answer(c, &receive(c, 1, 1), &found);
    let work = waiting(work);
    let mut attr = [0; 104];
    attr[16..].copy_from_slice(&found[40..]);
    answer(c, &receive(c, 3, 14), &attr);
    assert!(matches!(finish(work), Ok(FileValue::FuseStat(..))));
    receive(c, 2, 14);

    assert!(paths.readlink_at(AT_FDCWD, b"/mnt/link").is_none());
    let work = paths.take_fuse_stat().unwrap();
    answer(c, &receive(c, 1, 1), &found);
    let work = waiting(work);
    answer(c, &receive(c, 5, 14), b"../destination");
    assert!(matches!(finish(work),Ok(FileValue::Bytes(target)) if target==b"../destination"));
    receive(c, 2, 14);
}

#[test]
fn negative_lookup_bad_entry_and_trailing_slash_do_not_grant_access() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    for (path, payload, err, node) in [
        (b"/mnt/missing".as_slice(), entry(0, 0, 0).to_vec(), 2, None),
        (b"/mnt/bad", entry(24, 19, 0o100600)[..64].to_vec(), 5, None),
        (
            b"/mnt/file/",
            entry(25, 20, 0o100600).to_vec(),
            20,
            Some(25),
        ),
    ] {
        assert!(paths.access_at(AT_FDCWD, path, 0, false, false).is_none());
        let work = paths.take_fuse_stat().unwrap();
        let request = receive(c, 1, 1);
        let written = c.write(&reply(id(&request), 0, &payload));
        if payload.len() == 128 {
            assert_eq!(written, Ok(16 + payload.len()));
        } else {
            assert_eq!(written, Err(Errno(22)));
        }
        assert!(matches!(finish(work),Err(Errno(e)) if e==err));
        if let Some(node) = node {
            receive(c, 2, node);
        }
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn cancelled_lookup_forgets_late_or_already_arrived_reply() {
    let (_dev, c) = start();
    for cancel_first in [false, true] {
        let req = c.request(1, 1, Caller::default(), b"name\0").unwrap();
        let msg = receive(&c, 1, 1);
        if cancel_first {
            drop(req);
            answer(&c, &msg, &entry(40, 100, 0o100600));
        } else {
            answer(&c, &msg, &entry(40, 100, 0o100600));
            drop(req);
        }
        receive(&c, 2, 40);
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn namespace_metadata_projection_does_not_keep_an_unmounted_daemon_alive() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let metadata = mounts::Table::project(&v.mounts.as_ref().unwrap().0);
    v.umount(b"/mnt", 0).unwrap();
    assert_eq!(c.read(8192), Err(Errno(19)));
    assert!(metadata.mounts.iter().any(|m| m.fs.fuse.is_some()));
}

#[test]
fn reused_daemon_mounts_share_lifetime_and_cold_metadata_cannot_reconnect() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let fd = v
        .fds
        .entries()
        .iter()
        .find_map(|(&fd, d)| {
            matches!(
                d.open.borrow().control,
                Some(events::SharedControl::Fuse(_))
            )
            .then_some(fd)
        })
        .unwrap();
    let opts = format!("fd={fd},rootmode=40755,user_id=0,group_id=0");
    v.mkdir_at(AT_FDCWD, b"/other", 0o755).unwrap();
    v.mount(None, b"/other", Some(b"fuse"), 0, Some(opts.as_bytes()))
        .unwrap();
    let metadata = mounts::Table::project(&v.mounts.as_ref().unwrap().0);
    v.umount(b"/mnt", 0).unwrap();
    assert_eq!(c.read(8192), Err(Errno(11)));
    v.umount(b"/other", 0).unwrap();
    assert_eq!(c.read(8192), Err(Errno(19)));
    assert_eq!(
        v.mount(None, b"/other", Some(b"fuse"), 0, Some(opts.as_bytes())),
        Err(Errno(16))
    );
    assert!(metadata.mounts.iter().any(|m| m.fs.fuse.is_some()));
}

#[test]
fn lazy_unmount_keeps_an_open_file_and_implicit_flush_alive() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_file(&v, c, 0);
    let metadata = mounts::Table::project(&v.mounts.as_ref().unwrap().0);
    v.umount(b"/mnt", 2).unwrap();
    assert_eq!(c.read(8192), Err(Errno(11)));
    v.close(fd).unwrap();
    let flush = receive(c, 25, 10);
    answer(c, &flush, &[]);
    assert_eq!(c.read(8192), Err(Errno(19)));
    assert!(metadata.mounts.iter().any(|m| m.fs.fuse.is_some()));
    drop(paths);
}

pub(super) fn open_file(v: &Vfs, c: &Connection, flags: u32) -> (PathQueries, u32) {
    open_file_with_mode(v, c, flags, 0o100600)
}
fn open_file_with_mode(v: &Vfs, c: &Connection, flags: u32, mode: u32) -> (PathQueries, u32) {
    let files = FileEpoch::default().capture(v, true);
    let paths = v.path_queries();
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/data", flags, 0, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    answer(c, &receive(c, 1, 1), &entry(10, 210, mode));
    let work = waiting(work);
    let mut handle = [0; 16];
    handle[..8].copy_from_slice(&9876u64.to_le_bytes());
    answer(c, &receive(c, 14, 10), &handle);
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    (paths, fd as u32)
}
fn no_capabilities(c: &Connection, work: FileWork) -> FileWork {
    let query = receive(c, 22, 10);
    assert_eq!(&query[40..48], &[0; 8]);
    assert_eq!(&query[48..], b"security.capability\0");
    c.write(&reply(id(&query), -38, &[])).unwrap();
    waiting(work)
}

#[test]
fn sequential_write_and_read_share_position_but_positioned_read_does_not_wait() {
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
            bytes: b"hello".to_vec(),
            offset: None,
        },
    ));
    let write = no_capabilities(c, write);
    let wr = receive(c, 16, 10);
    assert_eq!(&wr[40..48], &9876u64.to_le_bytes());
    assert_eq!(&wr[80..], b"hello");
    let read = waiting(FileWork::new(
        &paths,
        target.clone(),
        FileCommand::Read {
            count: 8,
            offset: None,
        },
    ));
    assert!(!read.ready());
    let pread = waiting(FileWork::new(
        &paths,
        target,
        FileCommand::Read {
            count: 8,
            offset: Some(7),
        },
    ));
    let rd = receive(c, 15, 10);
    assert_eq!(&rd[48..56], &7u64.to_le_bytes());
    answer(c, &rd, b"z");
    assert!(matches!(finish(pread),Ok(FileValue::Bytes(b)) if b==b"z"));
    answer(c, &wr, &2u64.to_le_bytes());
    assert!(matches!(finish(write), Ok(FileValue::Count(2))));
    assert!(read.ready());
    let read = waiting(read);
    let rd = receive(c, 15, 10);
    assert_eq!(&rd[48..56], &2u64.to_le_bytes());
    answer(c, &rd, b"x");
    assert_eq!(finish(read).unwrap().into_bytes().unwrap(), b"x");
}

#[test]
fn dup_shares_handle_flush_error_consumes_slot_and_release_follows_last_close() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_file(&v, c, 2);
    let files = v.shared_files();
    let dup = files.duplicate(fd, 0, false).unwrap().unwrap();
    let flush = paths.close_file(&files, fd, 7).unwrap().unwrap().unwrap();
    let req = receive(c, 25, 10);
    c.write(&reply(id(&req), -5, &[])).unwrap();
    assert!(matches!(finish(flush), Err(Errno(5))));
    assert!(matches!(files.lookup(fd), Some(Err(Errno(9)))));
    assert_eq!(c.read(8192), Err(Errno(11)));
    files.close_range(dup, dup, 0, 7).unwrap();
    let req = receive(c, 25, 10);
    assert_eq!(c.read(8192), Err(Errno(11)));
    answer(c, &req, &[]);
    let rel = receive(c, 18, 10);
    assert_eq!(&rel[40..48], &9876u64.to_le_bytes());
    answer(c, &rel, &[]);
    receive(c, 2, 10);
}

#[test]
fn abandoned_open_releases_handle_granted_after_interrupt() {
    let (_dev, c) = start();
    for (open, release) in [(14, 18), (27, 29)] {
        for cancel_first in [false, true] {
            let req = c.request(open, 13, Caller::default(), &[0; 8]).unwrap();
            let msg = receive(&c, open, 13);
            let mut handle = [0; 16];
            handle[..8].copy_from_slice(&456u64.to_le_bytes());
            if cancel_first {
                drop(req);
                answer(&c, &msg, &handle);
            } else {
                answer(&c, &msg, &handle);
                drop(req);
            }
            let rel = receive(&c, release, 13);
            assert_eq!(&rel[40..48], &456u64.to_le_bytes());
            answer(&c, &rel, &[]);
            assert_eq!(c.read(8192), Err(Errno(11)));
        }
    }
}

pub(super) fn open_directory(v: &Vfs, c: &Connection, root: bool) -> (PathQueries, u32) {
    let files = FileEpoch::default().capture(v, true);
    let paths = v.path_queries();
    assert!(paths
        .open_at_resolve(
            AT_FDCWD,
            if root { b"/mnt" } else { b"/mnt/directory" },
            O_DIRECTORY,
            0,
            0,
            &files
        )
        .is_none());
    let mut work = paths.take_open_work().unwrap();
    let node = if root { 1 } else { 70 };
    let found = entry(node, 230, 0o40755);
    if root {
        let mut attr = [0; 104];
        attr[16..].copy_from_slice(&found[40..]);
        answer(c, &receive(c, 3, 1), &attr);
    } else {
        answer(c, &receive(c, 1, 1), &found);
    }
    work = waiting(work);
    let mut handle = [0; 16];
    handle[..8].copy_from_slice(&731u64.to_le_bytes());
    answer(c, &receive(c, 27, node), &handle);
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    (paths, fd as u32)
}
fn dirent(ino: u64, cookie: u64, name: &[u8], kind: u32) -> Vec<u8> {
    let mut bytes = vec![0; (24 + name.len() + 7) & !7];
    bytes[..8].copy_from_slice(&ino.to_le_bytes());
    bytes[8..16].copy_from_slice(&cookie.to_le_bytes());
    bytes[16..20].copy_from_slice(&(name.len() as u32).to_le_bytes());
    bytes[20..24].copy_from_slice(&kind.to_le_bytes());
    bytes[24..24 + name.len()].copy_from_slice(name);
    bytes
}
fn readdir(paths: &PathQueries, fd: u32, count: usize) -> FileWork {
    waiting(
        paths
            .fuse_file_work(fd, FileCommand::ReadDirectory { count })
            .unwrap()
            .unwrap(),
    )
}
fn directory_reply(work: FileWork) -> DirectoryReply {
    let FileValue::Directory(reply) = finish(work).unwrap() else {
        panic!()
    };
    reply
}

#[test]
fn directory_cookies_commit_after_guest_copy_and_dup_waits_on_original_position() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_directory(&v, c, true);
    let files = v.shared_files();
    let dup = files.duplicate(fd, 0, false).unwrap().unwrap();
    let read = readdir(&paths, fd, 64);
    let request = receive(c, 28, 1);
    assert_eq!(&request[40..48], &731u64.to_le_bytes());
    assert_eq!(&request[48..56], &0u64.to_le_bytes());
    let mut bytes = dirent(40, 9, b"a", 8);
    bytes.extend(dirent(41, 777, b"long", 4));
    answer(c, &request, &bytes);
    let reply = directory_reply(read);
    let seek = waiting(
        paths
            .fuse_file_work(
                dup,
                FileCommand::Seek {
                    offset: 0,
                    whence: 1,
                },
            )
            .unwrap()
            .unwrap(),
    );
    assert!(
        !seek.ready(),
        "ready daemon data must still retain its copy-out transaction"
    );
    assert_eq!(
        reply.copy_to(|offset, record| {
            if offset != 0 {
                return Err(Errno(14));
            }
            assert_eq!(&record[8..16], &9u64.to_le_bytes());
            assert_eq!(record[18], 8);
            assert_eq!(&record[19..21], b"a\0");
            Ok(())
        }),
        Ok(24)
    );
    assert!(seek.ready());
    assert!(matches!(finish(seek), Ok(FileValue::Count(9))));
    let eof = readdir(&paths, dup, 64);
    let request = receive(c, 28, 1);
    assert_eq!(&request[48..56], &9u64.to_le_bytes());
    answer(c, &request, &[]);
    assert_eq!(
        directory_reply(eof).copy_to(|_, _| panic!("EOF has no entries")),
        Ok(0)
    );
    assert!(matches!(
        finish(
            paths
                .fuse_file_work(
                    dup,
                    FileCommand::Seek {
                        offset: 0,
                        whence: 0
                    }
                )
                .unwrap()
                .unwrap()
        ),
        Ok(FileValue::Count(0))
    ));
    files.close_range(fd, fd, 0, 1).unwrap();
    assert_eq!(c.read(8192), Err(Errno(11)));
    files.close_range(dup, dup, 0, 1).unwrap();
    answer(c, &receive(c, 29, 1), &[]);
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "root has no LOOKUP reference to forget"
    );
}

#[test]
fn directory_small_buffers_malformed_replies_and_cancellation_preserve_cookie() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_directory(&v, c, false);
    for (capacity, bytes, errno) in [
        (1, dirent(40, 99, b"name", 8), 22),
        (64, dirent(40, 99, b"", 8), 5),
        (64, dirent(40, 99, b"bad/name", 8), 5),
    ] {
        let read = readdir(&paths, fd, capacity);
        let request = receive(c, 28, 70);
        assert_eq!(&request[48..56], &0u64.to_le_bytes());
        answer(c, &request, &bytes);
        assert_eq!(
            directory_reply(read).copy_to(|_, _| panic!("invalid entry cannot reach guest")),
            Err(Errno(errno))
        );
    }
    let read = readdir(&paths, fd, 64);
    answer(c, &receive(c, 28, 70), &dirent(40, 99, b"name", 8));
    drop(directory_reply(read));
    let read = readdir(&paths, fd, 64);
    let request = receive(c, 28, 70);
    assert_eq!(&request[48..56], &0u64.to_le_bytes());
    c.abort();
    assert!(matches!(finish(read), Err(Errno(103))));
}

#[test]
fn accepted_directory_reply_retains_the_last_handle_until_copy_or_cancellation() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_directory(&v, c, false);
    let read = readdir(&paths, fd, 64);
    let request = receive(c, 28, 70);
    v.shared_files().close_range(fd, fd, 0, 1).unwrap();
    assert_eq!(c.read(8192), Err(Errno(11)));
    answer(c, &request, &dirent(40, 99, b"a", 8));
    let reply = directory_reply(read);
    assert_eq!(c.read(8192), Err(Errno(11)));
    drop(reply);
    answer(c, &receive(c, 29, 70), &[]);
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn negotiated_large_io_keeps_short_results_and_position() {
    let (v, dev) = mounted_with_limit(16 * 1024);
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
            bytes: vec![42; 32 * 1024],
            offset: None,
        },
    ));
    let write = no_capabilities(c, write);
    let request = c.read(64 * 1024).unwrap();
    assert_eq!(op(&request), 16);
    assert_eq!(request.len(), 80 + 16 * 1024);
    assert_eq!(&request[56..60], &(16 * 1024u32).to_le_bytes());
    answer(c, &request, &8193u64.to_le_bytes());
    assert!(matches!(finish(write), Ok(FileValue::Count(8193))));
    let read = waiting(FileWork::new(
        &paths,
        target,
        FileCommand::Read {
            count: 32 * 1024,
            offset: None,
        },
    ));
    let request = receive(c, 15, 10);
    assert_eq!(&request[48..56], &8193u64.to_le_bytes());
    assert_eq!(&request[56..60], &(16 * 1024u32).to_le_bytes());
    answer(c, &request, &vec![11; 8193]);
    let bytes = finish(read).unwrap().into_bytes().unwrap();
    assert!(bytes.len() == 8193 && bytes.iter().all(|x| *x == 11));
}
