// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn reply(id: u64, error: i32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(((16 + payload.len()) as u32).to_le_bytes());
    bytes.extend(error.to_le_bytes());
    bytes.extend(id.to_le_bytes());
    bytes.extend(payload);
    bytes
}
fn id(bytes: &[u8]) -> u64 {
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
    assert_eq!(c.write(&reply(id(&init), 0, &[])), Err(Errno(22)));
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
    c.write(&reply(id(&msg), 0, b"stat")).unwrap();
    assert_eq!(req.take(), Some(Ok(b"stat".to_vec())));
    assert_eq!(c.write(&reply(id(&msg), 0, b"twice")), Err(Errno(2)));
}
#[test]
fn interrupt_priority_retry_disable_and_reply_races() {
    let (_dev, c) = start();
    let a = c.request(3, 1, Caller::default(), &[]).unwrap();
    let b = c.request(17, 1, Caller::default(), &[]).unwrap();
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
    assert_eq!(op(&next), 17);
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
    let mk = || c.request(3, 1, Caller::default(), &[]).unwrap();
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
        let request = connection.request(3, 1, Caller::default(), &[]).unwrap();
        assert!(signal.ready());
        let msg = connection.read(8192).unwrap();
        connection.write(&reply(id(&msg), 0, &[])).unwrap();
        assert_eq!(request.take(), Some(Ok(vec![])));
    }
}

fn mounted() -> (Vfs, Arc<Device>) {
    let mut v = Vfs::default();
    v.set_runtime_info(1, RuntimeInfo::default());
    v.mkdir_at(AT_FDCWD, b"/mnt", 0o755).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/dev/fuse", 2, 0).unwrap();
    let device = v.fuse_device(fd).unwrap().unwrap();
    let opts = format!("fd={fd},rootmode=40755,user_id=0,group_id=0");
    v.mount(None, b"/mnt", Some(b"fuse"), 0, Some(opts.as_bytes()))
        .unwrap();
    let c = device.connection().unwrap();
    let init = c.read(8192).unwrap();
    let mut version = [0; 64];
    version[..4].copy_from_slice(&7u32.to_le_bytes());
    version[4..8].copy_from_slice(&31u32.to_le_bytes());
    c.write(&reply(id(&init), 0, &version)).unwrap();
    (v, device)
}

fn entry(node: u64, ino: u64, mode: u32) -> [u8; 128] {
    let mut entry = [0; 128];
    entry[..8].copy_from_slice(&node.to_le_bytes());
    entry[24..32].copy_from_slice(&1u64.to_le_bytes());
    entry[40..48].copy_from_slice(&ino.to_le_bytes());
    entry[100..104].copy_from_slice(&mode.to_le_bytes());
    entry
}
fn receive(c: &Connection, opcode: u32, node: u64) -> Vec<u8> {
    let bytes = c.read(8192).unwrap();
    assert_eq!(op(&bytes), opcode);
    assert_eq!(u64::from_le_bytes(bytes[16..24].try_into().unwrap()), node);
    bytes
}
fn answer(c: &Connection, req: &[u8], body: &[u8]) {
    c.write(&reply(id(req), 0, body)).unwrap();
}
fn waiting(work: FileWork) -> FileWork {
    match work.run() {
        FileOutcome::Waiting(work) => work,
        _ => panic!("next daemon operation should be pending"),
    }
}
fn finish(work: FileWork) -> Result<FileValue> {
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
    for node in [22, 23] {
        let forget = receive(c, 2, node);
        assert_eq!(&forget[40..], &1u64.to_le_bytes());
        assert_eq!(c.write(&reply(id(&forget), 0, &[])), Err(Errno(2)));
    }
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
        (
            b"/mnt/bad",
            entry(24, 19, 0o100600)[..64].to_vec(),
            5,
            Some(24),
        ),
        (
            b"/mnt/file/",
            entry(25, 20, 0o100600).to_vec(),
            20,
            Some(25),
        ),
    ] {
        assert!(paths.access_at(AT_FDCWD, path, 0, false, false).is_none());
        let work = paths.take_fuse_stat().unwrap();
        answer(c, &receive(c, 1, 1), &payload);
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

fn open_file(v: &Vfs, c: &Connection, flags: u32) -> (PathQueries, u32) {
    let files = FileEpoch::default().capture(v, true);
    let paths = v.path_queries();
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/data", flags, 0, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    answer(c, &receive(c, 1, 1), &entry(10, 210, 0o100600));
    let work = waiting(work);
    let mut handle = [0; 16];
    handle[..8].copy_from_slice(&9876u64.to_le_bytes());
    answer(c, &receive(c, 14, 10), &handle);
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    (paths, fd as u32)
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
    assert!(matches!(finish(read),Ok(FileValue::Bytes(b)) if b==b"x"));
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
    let req = c.request(14, 13, Caller::default(), &[0; 8]).unwrap();
    let msg = receive(&c, 14, 13);
    drop(req);
    let mut handle = [0; 16];
    handle[..8].copy_from_slice(&456u64.to_le_bytes());
    answer(&c, &msg, &handle);
    let rel = receive(&c, 18, 13);
    assert_eq!(&rel[40..48], &456u64.to_le_bytes());
    answer(&c, &rel, &[]);
    assert_eq!(c.read(8192), Err(Errno(11)));
}
