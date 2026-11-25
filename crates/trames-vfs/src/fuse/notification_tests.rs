// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::fuse::tests::{
    answer, entry, finish, mounted, mounted_with_limit, open_directory, open_file, receive, reply,
    waiting,
};
use trames_memory::PAGE_SIZE;

fn file(v: &Vfs, c: &Arc<Connection>) -> (SharedFd, Arc<File>) {
    let (_paths, fd) = open_file(v, c, 0);
    let original = v.shared_files().lookup(fd).unwrap().unwrap();
    let Some(events::SharedControl::FuseFile(file)) = &original.open.control else {
        panic!("FUSE OFD");
    };
    let file = file.clone();
    file.attr.lock().unwrap()[8..16].copy_from_slice(&(64 * PAGE_SIZE).to_le_bytes());
    file.attr.lock().unwrap()[64..68].copy_from_slice(&1u32.to_le_bytes());
    file.inode().unwrap().borrow_mut().links = 1;
    (original, file)
}
fn apply(v: &mut Vfs, c: &Arc<Connection>, code: i32, body: &[u8]) -> Result<u64> {
    let packet = reply(0, code, body);
    let mut accepted = prepare(v, c, &packet)?.expect("notification");
    assert!(accepted.ready());
    match accepted.take(v).expect("inline notification")? {
        FileValue::Count(count) => Ok(count),
        _ => panic!("device write result"),
    }
}
fn store(v: &mut Vfs, c: &Arc<Connection>, offset: u64, bytes: &[u8]) {
    let mut body = vec![0; 24];
    body[..8].copy_from_slice(&10u64.to_le_bytes());
    body[8..16].copy_from_slice(&offset.to_le_bytes());
    body[16..20].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(bytes);
    assert_eq!(apply(v, c, 4, &body), Ok((16 + body.len()) as u64));
}
fn retrieve(v: &mut Vfs, c: &Arc<Connection>, offset: u64, count: u32) -> Vec<u8> {
    let mut body = [0; 32];
    body[..8].copy_from_slice(&0xfeedu64.to_le_bytes());
    body[8..16].copy_from_slice(&10u64.to_le_bytes());
    body[16..24].copy_from_slice(&offset.to_le_bytes());
    body[24..28].copy_from_slice(&count.to_le_bytes());
    assert_eq!(apply(v, c, 5, &body), Ok(48));
    let packet = c.read(1024 * 1024).unwrap();
    assert_eq!(u32::from_le_bytes(packet[4..8].try_into().unwrap()), 41);
    assert_eq!(
        u64::from_le_bytes(packet[8..16].try_into().unwrap()),
        0xfeed
    );
    assert_eq!(u64::from_le_bytes(packet[16..24].try_into().unwrap()), 10);
    assert_eq!(
        u64::from_le_bytes(packet[48..56].try_into().unwrap()),
        offset
    );
    assert_eq!(
        u32::from_le_bytes(packet[56..60].try_into().unwrap()) as usize,
        packet.len() - 80
    );
    packet[80..].to_vec()
}
#[test]
fn partial_store_is_visible_to_retrieve_without_completing_a_normal_read_page() {
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (_original, file) = file(&v, c);
    store(&mut v, c, 7, b"abc");
    let bytes = retrieve(&mut v, c, 0, 16);
    assert_eq!(&bytes[7..10], b"abc");
    assert_eq!(&bytes[..7], &[0; 7]);
    assert_eq!(&bytes[10..], &[0; 6]);
    assert!(file.attr.cache.cached(0, 16).is_none());
    assert_eq!(c.read(8192), Err(Errno(11)));
}
#[test]
fn retrieve_stops_at_the_first_absent_page_and_does_not_skip_to_later_data() {
    let (mut v, dev) = mounted_with_limit(128 * 1024);
    let c = &dev.daemon.get().unwrap().connection;
    let (_original, _file) = file(&v, c);
    store(&mut v, c, PAGE_SIZE - 4, b"tail");
    store(&mut v, c, 2 * PAGE_SIZE, b"later");
    assert_eq!(
        retrieve(&mut v, c, PAGE_SIZE - 4, (2 * PAGE_SIZE) as u32),
        b"tail"
    );
    assert!(retrieve(&mut v, c, PAGE_SIZE, 8).is_empty());
}
#[test]
fn unaligned_retrieve_obeys_the_negotiated_bytes_and_default_32_page_ceiling() {
    let (mut v, dev) = mounted_with_limit(128 * 1024);
    let c = &dev.daemon.get().unwrap().connection;
    let (_original, _file) = file(&v, c);
    let bytes = vec![9; (33 * PAGE_SIZE) as usize];
    store(&mut v, c, 0, &bytes);
    let bytes = retrieve(&mut v, c, 1, u32::MAX);
    assert_eq!(bytes.len(), (32 * PAGE_SIZE - 1) as usize);
    assert!(bytes.iter().all(|&byte| byte == 9));
}
#[test]
fn retrieve_at_and_beyond_eof_queues_an_empty_reply_with_the_original_offset() {
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (_original, _file) = file(&v, c);
    for offset in [64 * PAGE_SIZE, u64::MAX] {
        assert!(retrieve(&mut v, c, offset, 4096).is_empty());
    }
}
#[test]
fn notification_name_limit_precedes_packet_length_and_uses_fuse_name_max() {
    let (v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    for code in [3, 6] {
        let header = if code == 3 { 16 } else { 24 };
        let length_at = header - 8;
        let mut body = vec![0; header];
        body[..8].copy_from_slice(&1u64.to_le_bytes());
        body[length_at..length_at + 4].copy_from_slice(&1025u32.to_le_bytes());
        assert!(matches!(
            prepare(&v, c, &reply(0, code, &body)),
            Err(Errno(36))
        ));
        body[length_at..length_at + 4].copy_from_slice(&1024u32.to_le_bytes());
        body.extend(vec![b'x'; 1024]);
        body.push(0);
        assert!(prepare(&v, c, &reply(0, code, &body)).unwrap().is_some());
    }
}

fn named(parent: u64, child: Option<u64>, name: &[u8], flags: u32) -> Vec<u8> {
    let header = if child.is_some() { 24 } else { 16 };
    let mut body = vec![0; header];
    body[..8].copy_from_slice(&parent.to_le_bytes());
    if let Some(child) = child {
        body[8..16].copy_from_slice(&child.to_le_bytes());
    } else {
        body[12..16].copy_from_slice(&flags.to_le_bytes());
    }
    body[header - 8..header - 4].copy_from_slice(&(name.len() as u32).to_le_bytes());
    body.extend_from_slice(name);
    body.push(0xff); // Native forces this copied terminator to NUL.
    body
}

#[test]
fn entry_notifications_require_the_original_name_and_expiration_preserves_its_hash() {
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (_original, file) = file(&v, c);
    for name in [b"absent".as_slice(), b"", b"data/child", b"data\0"] {
        assert_eq!(apply(&mut v, c, 3, &named(1, None, name, 0)), Err(Errno(2)));
    }
    let body = named(1, None, b"data", 1);
    for _ in 0..2 {
        assert_eq!(apply(&mut v, c, 3, &body), Ok((16 + body.len()) as u64));
    }
    let body = named(1, None, b"data", 0);
    assert_eq!(apply(&mut v, c, 3, &body), Ok((16 + body.len()) as u64));
    assert_eq!(apply(&mut v, c, 3, &body), Err(Errno(2)));
    assert_eq!(
        file.fh,
        Some(9876),
        "the original open handle survives unhashing"
    );
    assert_ne!(
        u32::from_le_bytes(file.attr.lock().unwrap()[64..68].try_into().unwrap()),
        0
    );
}

#[test]
fn delete_checks_the_named_child_before_zeroing_links_and_does_not_retarget_an_old_ofd() {
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (original, old_file) = file(&v, c);
    let links = u32::from_le_bytes(old_file.attr.lock().unwrap()[64..68].try_into().unwrap());
    let wrong = named(1, Some(11), b"data", 0);
    assert_eq!(apply(&mut v, c, 6, &wrong), Err(Errno(2)));
    assert_eq!(
        u32::from_le_bytes(old_file.attr.lock().unwrap()[64..68].try_into().unwrap()),
        links
    );
    assert_eq!(
        apply(&mut v, c, 6, &named(1, Some(10), b"data", 0)),
        Err(Errno(2)),
        "the mismatched DELETE already unhashed that name"
    );
    let (_new_original, new_file) = file(&v, c);
    assert!(Arc::ptr_eq(&old_file.attr, &new_file.attr));
    let body = named(1, Some(10), b"data", 0);
    assert_eq!(apply(&mut v, c, 6, &body), Ok((16 + body.len()) as u64));
    assert_eq!(
        u32::from_le_bytes(old_file.attr.lock().unwrap()[64..68].try_into().unwrap()),
        0
    );
    assert_eq!(
        original
            .open
            .control
            .as_ref()
            .and_then(|control| match control {
                events::SharedControl::FuseFile(file) => file.fh,
                _ => None,
            }),
        Some(9876)
    );
}

fn namespace(v: &Vfs, call: NamespaceCall) -> u64 {
    let paths = v.path_queries();
    let reply = match paths.namespace_attempt(call) {
        NamespaceAttempt::Complete(reply) => reply,
        NamespaceAttempt::Retained(work) => match work.run() {
            FileOutcome::Complete(reply) => reply,
            _ => panic!("uncontended descriptor mount operation"),
        },
    };
    let FileValue::Count(count) = reply.result.unwrap() else {
        panic!("mount result")
    };
    count
}
fn tmpfs(v: &mut Vfs) -> u32 {
    let context = namespace(
        v,
        NamespaceCall::MountFd(MountFdCall::Open {
            kind: b"tmpfs".to_vec(),
            flags: 0,
        }),
    ) as u32;
    assert_eq!(
        namespace(
            v,
            NamespaceCall::MountFd(MountFdCall::Config {
                fd: context,
                cmd: 6,
                key: None,
                value: None
            })
        ),
        0
    );
    let tree = namespace(
        v,
        NamespaceCall::MountFd(MountFdCall::Mount {
            fd: context,
            flags: 0,
            attrs: 0,
        }),
    ) as u32;
    v.close(context).unwrap();
    tree
}
fn attach(v: &Vfs, tree: u32, target: u32) {
    assert_eq!(
        namespace(
            v,
            NamespaceCall::MountFd(MountFdCall::Move {
                from: tree as i32,
                source: Vec::new(),
                to: target as i32,
                target: Vec::new(),
                flags: 4 | 0x40,
            })
        ),
        0
    );
}
fn temporary_mounts(v: &Vfs) -> Vec<u64> {
    v.mounts
        .as_ref()
        .unwrap()
        .0
        .borrow()
        .mounts
        .iter()
        .filter(|mount| mount.kind == mounts::Kind::Tmpfs)
        .map(|mount| mount.id)
        .collect()
}

#[test]
fn open_tree_path_and_cloned_leaf_keep_the_original_name_without_opening_another_handle() {
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (paths, source) = open_file(&v, c, 0);
    let original = v.shared_files().lookup(source).unwrap().unwrap();
    let Some(events::SharedControl::FuseFile(file)) = &original.open.control else {
        panic!("original file")
    };
    let name = Arc::downgrade(file.reference.entry.as_ref().unwrap());
    let inode = Arc::downgrade(&file.inode().unwrap());
    let path = namespace(
        &v,
        NamespaceCall::MountFd(MountFdCall::Tree {
            fd: source as i32,
            path: Vec::new(),
            flags: 0x1000 | O_CLOEXEC,
        }),
    ) as u32;
    let cloned = namespace(
        &v,
        NamespaceCall::MountFd(MountFdCall::Tree {
            fd: path as i32,
            path: Vec::new(),
            flags: 0x1000 | 1,
        }),
    ) as u32;
    assert_eq!(c.read(8192), Err(Errno(11)), "path opens issue no OPEN");
    drop(original);
    drop(paths);
    v.close(source).unwrap();
    assert_eq!(v.eventfd(99, 0).unwrap(), source);
    let flush = crate::fuse::tests::receive(c, 25, 10);
    answer(c, &flush, &[]);
    let expired = named(1, None, b"data", 1);
    assert_eq!(
        apply(&mut v, c, 3, &expired),
        Ok((16 + expired.len()) as u64)
    );
    v.close(path).unwrap();
    assert!(name.upgrade().is_some() && inode.upgrade().is_some());
    assert_eq!(
        apply(&mut v, c, 3, &expired),
        Ok((16 + expired.len()) as u64)
    );
    v.close(cloned).unwrap();
    v.reap_detached_mounts();
    assert!(name.upgrade().is_none() && inode.upgrade().is_none());
    assert_eq!(apply(&mut v, c, 3, &expired), Err(Errno(2)));
    assert_eq!(v.read(source, 8).unwrap(), 99u64.to_le_bytes());
    let mut releases = 0;
    let mut forgets = 0;
    for _ in 0..8 {
        let request = match c.read(8192) {
            Ok(request) => request,
            Err(Errno(11)) => break,
            Err(error) => panic!("release read failed: {error:?}"),
        };
        assert_eq!(u64::from_le_bytes(request[16..24].try_into().unwrap()), 10);
        match u32::from_le_bytes(request[4..8].try_into().unwrap()) {
            18 => releases += 1,
            2 => forgets += 1,
            opcode => panic!("unexpected path descriptor request {opcode}"),
        }
    }
    assert_eq!((releases, forgets), (1, 1));
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn entry_invalidation_detaches_all_namespace_aliases_and_keeps_original_tree_descriptors_usable() {
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (_paths, dir) = open_directory(&v, c, false);
    let tree = tmpfs(&mut v);
    attach(&v, tree, dir);
    let marker = v
        .open_at(tree as i32, b"marker", O_CREAT | 2, 0o600)
        .unwrap();
    assert_eq!(v.write(marker, b"original tree"), Ok(13));
    let mut sibling = v.clone_with_resources(false, false);
    sibling.unshare_mounts().unwrap();
    assert!(!temporary_mounts(&v).is_empty());
    assert!(!temporary_mounts(&sibling).is_empty());
    let body = named(1, None, b"directory", 0);
    assert_eq!(apply(&mut v, c, 3, &body), Ok((16 + body.len()) as u64));
    assert!(temporary_mounts(&v).is_empty());
    assert!(temporary_mounts(&sibling).is_empty());
    v.seek(marker, 0, 0).unwrap();
    assert_eq!(v.read(marker, 64).unwrap(), b"original tree");
    v.mkdir_at(AT_FDCWD, b"/reattached", 0o755).unwrap();
    assert_eq!(
        namespace(
            &v,
            NamespaceCall::MountFd(MountFdCall::Move {
                from: tree as i32,
                source: Vec::new(),
                to: AT_FDCWD,
                target: b"/reattached".to_vec(),
                flags: 4,
            })
        ),
        0
    );
    assert_eq!(temporary_mounts(&v).len(), 1);
    assert_eq!(apply(&mut v, c, 3, &body), Err(Errno(2)));
    assert_eq!(
        temporary_mounts(&v).len(),
        1,
        "a later notification cannot discover the old name again"
    );
}

#[test]
fn contended_entry_invalidation_parks_on_original_namespace_and_keeps_fd_reuse_out_of_completion() {
    struct Wake;
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (_paths, dir) = open_directory(&v, c, false);
    let tree = tmpfs(&mut v);
    attach(&v, tree, dir);
    let admin = v.mount_admin().unwrap();
    let held = admin.enter();
    let packet = reply(0, 3, &named(1, None, b"directory", 0));
    let mut pending = prepare(&v, c, &packet).unwrap().unwrap();
    assert!(pending.take(&mut v).is_none());
    assert!(!pending.ready());
    let target: Arc<dyn IoWake> = Arc::new(Wake);
    let signal = IoSignal::new(1, Arc::downgrade(&target));
    let _subscription = pending.subscribe(&signal).unwrap();
    v.close(dir).unwrap();
    assert_eq!(v.eventfd(99, 0).unwrap(), dir);
    assert_eq!(temporary_mounts(&v).len(), 1);
    drop(held);
    assert!(signal.ready() && pending.ready());
    assert!(
        matches!(pending.take(&mut v), Some(Ok(FileValue::Count(n))) if n == packet.len() as u64)
    );
    assert!(temporary_mounts(&v).is_empty());
    assert_eq!(v.read(dir, 8).unwrap(), 99u64.to_le_bytes());
    v.mkdir_at(AT_FDCWD, b"/again", 0o755).unwrap();
    assert_eq!(
        namespace(
            &v,
            NamespaceCall::MountFd(MountFdCall::Move {
                from: tree as i32,
                source: Vec::new(),
                to: AT_FDCWD,
                target: b"/again".to_vec(),
                flags: 4,
            })
        ),
        0
    );
    assert!(matches!(
        pending.take(&mut v),
        Some(Ok(FileValue::Count(_)))
    ));
    assert_eq!(
        temporary_mounts(&v).len(),
        1,
        "completed receipt cannot detach again"
    );
}

#[test]
fn executor_failure_releases_the_original_namespace_retry_and_does_not_replay_accepted_unhash() {
    struct Completion {
        _resource: Arc<Notification>,
        results: Arc<Mutex<Vec<std::result::Result<(), MemoryError>>>>,
    }
    impl SyncCompletion for Completion {
        fn complete(self: Box<Self>, result: std::result::Result<(), MemoryError>) {
            self.results.lock().unwrap().push(result);
        }
        fn retry(self: Box<Self>) {
            panic!("failed executor cannot be requeued")
        }
    }
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (_paths, dir) = open_directory(&v, c, false);
    let tree = tmpfs(&mut v);
    attach(&v, tree, dir);
    let admin = v.mount_admin().unwrap();
    let held = admin.enter();
    let body = named(1, None, b"directory", 0);
    let pending = prepare(&v, c, &reply(0, 3, &body)).unwrap().unwrap();
    let ResultKind::Notification(resource, _) = &pending.kind else {
        panic!("original inline resource")
    };
    let resource = resource.clone();
    let original = Arc::downgrade(&resource);
    let results = Arc::new(Mutex::new(Vec::new()));
    assert!(resource
        .sync_async(Box::new(Completion {
            _resource: resource.clone(),
            results: results.clone()
        }))
        .is_ok());
    resource.failed(MemoryError::BackingIo(5));
    assert!(matches!(
        results.lock().unwrap().as_slice(),
        [Err(MemoryError::BackingIo(5))]
    ));
    drop(pending);
    drop(resource);
    assert!(
        original.upgrade().is_none(),
        "failed continuation must not form an ownership cycle"
    );
    drop(held);
    assert_eq!(temporary_mounts(&v).len(), 1);
    assert_eq!(apply(&mut v, c, 3, &body), Err(Errno(2)));
}

#[test]
fn delete_preserves_a_directory_with_a_held_child_and_can_delete_after_that_child_is_released() {
    use crate::fuse::tests::{answer, entry};
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (_paths, dir) = open_directory(&v, c, false);
    let original = v.shared_files().lookup(dir).unwrap().unwrap();
    let Some(events::SharedControl::FuseFile(file)) = &original.open.control else {
        panic!("original directory")
    };
    let node = file.inode().unwrap();
    node.borrow_mut().links = 2;
    inode::attr(&node).lock().unwrap()[64..68].copy_from_slice(&2u32.to_le_bytes());
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(dir as i32, b"child", 0, 0, 0, &files)
        .is_none());
    let mut work = paths.take_open_work().unwrap();
    let mut child = None;
    for _ in 0..8 {
        work = match work.run() {
            FileOutcome::Complete(reply) => {
                let FileValue::Count(fd) = reply.result.unwrap() else {
                    panic!("child descriptor")
                };
                child = Some(fd as u32);
                break;
            }
            FileOutcome::Waiting(next) => next,
            _ => panic!("child lookup stays on the original source"),
        };
        let request = c.read(8192).unwrap();
        let opcode = u32::from_le_bytes(request[4..8].try_into().unwrap());
        let target = u64::from_le_bytes(request[16..24].try_into().unwrap());
        match (opcode, target) {
            (3, 70) => {
                let mut attr = [0; 104];
                attr[16..].copy_from_slice(&entry(70, 230, 0o40755)[40..]);
                attr[80..84].copy_from_slice(&2u32.to_le_bytes());
                answer(c, &request, &attr);
            }
            (1, 70) => answer(c, &request, &entry(71, 231, 0o100600)),
            (14, 71) => {
                let mut handle = [0; 16];
                handle[..8].copy_from_slice(&732u64.to_le_bytes());
                answer(c, &request, &handle);
            }
            _ => panic!("unexpected child request opcode={opcode} node={target}"),
        }
    }
    let child = child.expect("bounded child lookup completes");
    let body = named(1, Some(70), b"directory", 0);
    assert_eq!(apply(&mut v, c, 6, &body), Err(Errno(39)));
    assert!(node.fuse_directory.get().unwrap().linked());
    assert_ne!(
        u32::from_le_bytes(
            inode::attr(&node).lock().unwrap()[64..68]
                .try_into()
                .unwrap()
        ),
        0
    );
    drop(paths);
    drop(files);
    v.close(child).unwrap();
    for _ in 0..8 {
        let request = match c.read(8192) {
            Ok(request) => request,
            Err(Errno(11)) => break,
            Err(error) => panic!("child release read failed: {error:?}"),
        };
        let opcode = u32::from_le_bytes(request[4..8].try_into().unwrap());
        let target = u64::from_le_bytes(request[16..24].try_into().unwrap());
        if opcode == 25 && target == 71 {
            answer(c, &request, &[]);
            continue;
        }
        assert!(
            matches!(opcode, 2 | 18) && target == 71,
            "child release opcode={opcode} node={target}"
        );
    }
    assert_eq!(c.read(8192), Err(Errno(11)));
    // The next lookup may grant a fresh name for the same retained directory.
    let (_next_paths, _next_dir) = open_directory(&v, c, false);
    assert_eq!(apply(&mut v, c, 6, &body), Ok((16 + body.len()) as u64));
    assert!(!node.fuse_directory.get().unwrap().linked());
    assert_eq!(
        u32::from_le_bytes(
            inode::attr(&node).lock().unwrap()[64..68]
                .try_into()
                .unwrap()
        ),
        0
    );
}

#[test]
fn entry_invalidation_removes_mount_stacks_and_their_nested_subtrees_once() {
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (_paths, dir) = open_directory(&v, c, false);
    let first = tmpfs(&mut v);
    attach(&v, first, dir);
    v.mkdir_at(first as i32, b"nested", 0o755).unwrap();
    let nested_dir = v.open_at(first as i32, b"nested", O_DIRECTORY, 0).unwrap();
    let nested = tmpfs(&mut v);
    attach(&v, nested, nested_dir);
    let marker = v
        .open_at(nested as i32, b"marker", O_CREAT | 2, 0o600)
        .unwrap();
    v.write(marker, b"nested original").unwrap();
    let covered = tmpfs(&mut v);
    attach(&v, covered, dir);
    assert_eq!(temporary_mounts(&v).len(), 3);
    let body = named(1, None, b"directory", 0);
    assert_eq!(apply(&mut v, c, 3, &body), Ok((16 + body.len()) as u64));
    assert!(temporary_mounts(&v).is_empty());
    v.seek(marker, 0, 0).unwrap();
    assert_eq!(v.read(marker, 64).unwrap(), b"nested original");
    assert_eq!(apply(&mut v, c, 3, &body), Err(Errno(2)));
}

#[test]
fn entry_notification_waits_for_all_original_shared_lookups_including_cancelled_readers() {
    struct Wake;
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (_original, _file) = file(&v, c);
    let first = v.path_queries();
    let second = v.path_queries();
    assert!(first.statx_at(AT_FDCWD, b"/mnt/first", false).is_none());
    let cancelled = first.take_fuse_stat().unwrap();
    let _cancelled_request = receive(c, 1, 1);
    assert!(second.statx_at(AT_FDCWD, b"/mnt/second", false).is_none());
    let remaining = second.take_fuse_stat().unwrap();
    let accepted = receive(c, 1, 1);
    let packet = reply(0, 3, &named(1, None, b"data", 0));
    let mut pending = prepare(&v, c, &packet).unwrap().unwrap();
    assert!(pending.take(&mut v).is_none());
    assert!(!pending.ready());
    let target: Arc<dyn IoWake> = Arc::new(Wake);
    let signal = IoSignal::new(1, Arc::downgrade(&target));
    let _subscription = pending.subscribe(&signal).unwrap();
    let newcomer = v.path_queries();
    assert!(newcomer
        .statx_at(AT_FDCWD, b"/mnt/after-writer", false)
        .is_none());
    let queued = waiting(newcomer.take_fuse_stat().unwrap());
    assert!(
        !queued.ready(),
        "a new reader cannot pass the accepted writer"
    );
    assert_eq!(c.read(8192), Err(Errno(11)));
    drop(queued);
    drop(cancelled);
    assert!(
        !pending.ready(),
        "another original reader is still accepted"
    );
    answer(c, &accepted, &entry(90, 290, 0o100600));
    assert!(matches!(finish(remaining), Ok(FileValue::FuseStat(..))));
    assert!(signal.ready() && pending.ready());
    assert!(
        matches!(pending.take(&mut v), Some(Ok(FileValue::Count(n))) if n == packet.len() as u64)
    );
}

#[test]
fn cancelling_the_original_inode_writer_wakes_readers_without_waiting_for_other_readers() {
    struct Wake;
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (_original, file) = file(&v, c);
    let first = v.path_queries();
    assert!(first.statx_at(AT_FDCWD, b"/mnt/busy", false).is_none());
    let held = first.take_fuse_stat().unwrap();
    let busy = receive(c, 1, 1);
    let packet = reply(0, 3, &named(1, None, b"data", 0));
    let mut pending = prepare(&v, c, &packet).unwrap().unwrap();
    assert!(pending.take(&mut v).is_none() && !pending.ready());
    let next = v.path_queries();
    assert!(next.statx_at(AT_FDCWD, b"/mnt/new", false).is_none());
    let blocked = waiting(next.take_fuse_stat().unwrap());
    assert!(!blocked.ready());
    let target: Arc<dyn IoWake> = Arc::new(Wake);
    let signal = IoSignal::new(1, Arc::downgrade(&target));
    let _wait = blocked.wait_sources(&signal).unwrap();
    assert_eq!(c.read(8192), Err(Errno(11)));
    drop(pending);
    assert!(signal.ready() && blocked.ready());
    assert!(
        file.named_entry().unwrap().hashed(),
        "the cancelled write never selected its name"
    );
    let blocked = waiting(blocked);
    let request = receive(c, 1, 1);
    assert_eq!(&request[40..], b"new\0");
    answer(c, &request, &entry(92, 292, 0o100600));
    assert!(matches!(finish(blocked), Ok(FileValue::FuseStat(..))));
    answer(c, &busy, &entry(93, 293, 0o100600));
    assert!(matches!(finish(held), Ok(FileValue::FuseStat(..))));
}

#[test]
fn create_fallback_holds_the_original_parent_until_mknod_binds_the_name() {
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (_original, _file) = file(&v, c);
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/new", O_CREAT | 2, 0o600, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    let lookup = receive(c, 1, 1);
    c.write(&reply(
        u64::from_le_bytes(lookup[8..16].try_into().unwrap()),
        -2,
        &[],
    ))
    .unwrap();
    let work = waiting(work);
    let create = receive(c, 35, 1);
    c.write(&reply(
        u64::from_le_bytes(create[8..16].try_into().unwrap()),
        -38,
        &[],
    ))
    .unwrap();
    let work = waiting(work);
    let mknod = receive(c, 8, 1);
    let packet = reply(0, 3, &named(1, None, b"data", 0));
    let mut pending = prepare(&v, c, &packet).unwrap().unwrap();
    assert!(pending.take(&mut v).is_none() && !pending.ready());
    let observer = v.path_queries();
    assert!(observer.statx_at(AT_FDCWD, b"/mnt/peek", false).is_none());
    let blocked = waiting(observer.take_fuse_stat().unwrap());
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "a blocked lookup cannot send another request"
    );
    drop(blocked);
    answer(c, &mknod, &entry(91, 291, 0o100600));
    let work = waiting(work);
    let open = receive(c, 14, 91);
    assert!(pending.ready());
    assert!(matches!(
        pending.take(&mut v),
        Some(Ok(FileValue::Count(_)))
    ));
    answer(c, &open, &[0; 16]);
    assert!(matches!(finish(work), Ok(FileValue::Count(_))));
}

#[test]
fn delete_waits_for_the_original_child_write_and_keeps_accepted_unhash() {
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (paths, fd) = open_file(&v, c, 2);
    let original = v.shared_files().lookup(fd).unwrap().unwrap();
    let Some(events::SharedControl::FuseFile(file)) = &original.open.control else {
        panic!("original file")
    };
    let file = file.clone();
    file.attr.lock().unwrap()[64..68].copy_from_slice(&1u32.to_le_bytes());
    file.inode().unwrap().borrow_mut().links = 1;
    let work = waiting(FileWork::new(
        &paths,
        original.file_target().unwrap(),
        FileCommand::Write {
            bytes: b"abc".to_vec(),
            offset: None,
        },
    ));
    let capability = receive(c, 22, 10);
    c.write(&reply(
        u64::from_le_bytes(capability[8..16].try_into().unwrap()),
        -38,
        &[],
    ))
    .unwrap();
    let work = waiting(work);
    let write = receive(c, 16, 10);
    let packet = reply(0, 6, &named(1, Some(10), b"data", 0));
    let mut pending = prepare(&v, c, &packet).unwrap().unwrap();
    assert!(pending.take(&mut v).is_none() && !pending.ready());
    assert!(!file.named_entry().unwrap().hashed());
    assert_eq!(file.inode().unwrap().borrow().links, 1);
    let mut written = [0; 8];
    written[..4].copy_from_slice(&3u32.to_le_bytes());
    answer(c, &write, &written);
    assert!(matches!(finish(work), Ok(FileValue::Count(3))));
    assert!(pending.ready());
    assert!(matches!(
        pending.take(&mut v),
        Some(Ok(FileValue::Count(_)))
    ));
    assert_eq!(file.inode().unwrap().borrow().links, 0);
    assert_eq!(file.fh, Some(9876));
}

#[test]
fn delete_waits_until_the_original_readdir_reply_finishes_user_copy() {
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (paths, fd) = open_directory(&v, c, false);
    let original = v.shared_files().lookup(fd).unwrap().unwrap();
    let work = waiting(FileWork::new(
        &paths,
        original.file_target().unwrap(),
        FileCommand::ReadDirectory { count: 64 },
    ));
    let request = receive(c, 28, 70);
    let packet = reply(0, 6, &named(1, Some(70), b"directory", 0));
    let mut pending = prepare(&v, c, &packet).unwrap().unwrap();
    assert!(pending.take(&mut v).is_none() && !pending.ready());
    let mut record = [0; 32];
    record[..8].copy_from_slice(&123u64.to_le_bytes());
    record[8..16].copy_from_slice(&101u64.to_le_bytes());
    record[16..20].copy_from_slice(&3u32.to_le_bytes());
    record[20..24].copy_from_slice(&8u32.to_le_bytes());
    record[24..27].copy_from_slice(b"one");
    answer(c, &request, &record);
    let FileValue::Directory(directory) = finish(work).unwrap() else {
        panic!("directory reply")
    };
    assert!(pending.take(&mut v).is_none() && !pending.ready());
    let mut copied = Vec::new();
    assert_eq!(
        directory.copy_to(|at, bytes| {
            assert_eq!(at, copied.len());
            copied.extend_from_slice(bytes);
            Ok(())
        }),
        Ok(24)
    );
    assert_eq!(&copied[19..22], b"one");
    assert!(pending.ready());
    assert!(matches!(
        pending.take(&mut v),
        Some(Ok(FileValue::Count(_)))
    ));
    let Some(events::SharedControl::FuseFile(file)) = &original.open.control else {
        panic!("original directory")
    };
    assert!(!file.inode().unwrap().fuse_directory.get().unwrap().linked());
    assert_eq!(
        u32::from_le_bytes(file.attr.lock().unwrap()[64..68].try_into().unwrap()),
        0
    );
}

#[test]
fn alias_splicing_uses_native_try_admission_and_preserves_the_original_name_on_stale() {
    for busy_rename in [true, false] {
        let (v, dev) = mounted();
        let c = &dev.daemon.get().unwrap().connection;
        let (_old_paths, old) = open_directory(&v, c, false);
        let original = v.shared_files().lookup(old).unwrap().unwrap();
        let Some(events::SharedControl::FuseFile(file)) = &original.open.control else {
            panic!("old directory")
        };
        let node = file.inode().unwrap();
        let fs = file.reference.fs.clone();
        let paths = v.path_queries();
        let files = FileEpoch::default().capture(&v, true);
        assert!(paths
            .open_at_resolve(AT_FDCWD, b"/mnt/parent", O_DIRECTORY, 0, 0, &files)
            .is_none());
        let work = paths.take_open_work().unwrap();
        answer(c, &receive(c, 1, 1), &entry(80, 280, 0o40755));
        let work = waiting(work);
        answer(c, &receive(c, 27, 80), &[0; 16]);
        let FileValue::Count(parent) = finish(work).unwrap() else {
            panic!("new parent")
        };
        let files = FileEpoch::default().capture(&v, true);
        let begin = || {
            assert!(paths
                .open_at_resolve(parent as i32, b"alias", O_DIRECTORY, 0, 0, &files)
                .is_none());
            let mut work = paths.take_open_work().unwrap();
            for _ in 0..4 {
                let request = c.read(8192).unwrap();
                let opcode = u32::from_le_bytes(request[4..8].try_into().unwrap());
                assert_eq!(u64::from_le_bytes(request[16..24].try_into().unwrap()), 80);
                if opcode == 1 {
                    assert_eq!(&request[40..], b"alias\0");
                    return (work, request);
                }
                assert_eq!(opcode, 3);
                let mut attr = [0; 104];
                attr[16..].copy_from_slice(&entry(80, 280, 0o40755)[40..]);
                answer(c, &request, &attr);
                work = waiting(work);
            }
            panic!("bounded parent refresh reaches LOOKUP")
        };
        let (work, request) = begin();
        let root = fs.root_directory();
        let rename = busy_rename.then(|| fs.rename.try_enter().unwrap());
        let parent_write = (!busy_rename).then(|| inode::attr(&root).try_write().unwrap());
        answer(c, &request, &entry(70, 230, 0o40755));
        let mut work = waiting(work);
        let mut forgotten = 0;
        let mut retried = None;
        for _ in 0..8 {
            let request = c.read(8192).unwrap();
            match u32::from_le_bytes(request[4..8].try_into().unwrap()) {
                2 => {
                    assert_eq!(u64::from_le_bytes(request[16..24].try_into().unwrap()), 70);
                    forgotten += 1;
                }
                3 => {
                    assert_eq!(u64::from_le_bytes(request[16..24].try_into().unwrap()), 80);
                    let mut attr = [0; 104];
                    attr[16..].copy_from_slice(&entry(80, 280, 0o40755)[40..]);
                    answer(c, &request, &attr);
                    work = waiting(work);
                }
                1 => {
                    retried = Some(request);
                    break;
                }
                opcode => panic!("unexpected alias revalidation opcode {opcode}"),
            }
        }
        let request = retried.expect("one bounded pathname revalidation");
        assert_eq!(u64::from_le_bytes(request[16..24].try_into().unwrap()), 80);
        assert_eq!(&request[40..], b"alias\0");
        answer(c, &request, &entry(70, 230, 0o40755));
        assert!(matches!(finish(work), Err(Errno(116))));
        assert_eq!(
            node.fuse_directory.get().unwrap().path().unwrap(),
            b"/directory"
        );
        drop(parent_write);
        drop(rename);
        for _ in forgotten..2 {
            receive(c, 2, 70);
        }
        let (work, request) = begin();
        answer(c, &request, &entry(70, 230, 0o40755));
        let work = waiting(work);
        answer(c, &receive(c, 27, 70), &[0; 16]);
        let FileValue::Count(alias) = finish(work).unwrap() else {
            panic!("alias descriptor")
        };
        let opened = v.shared_files().lookup(alias as u32).unwrap().unwrap();
        let Some(events::SharedControl::FuseFile(file)) = &opened.open.control else {
            panic!("same original inode")
        };
        assert!(Arc::ptr_eq(&node, &file.inode().unwrap()));
        assert_eq!(
            node.fuse_directory.get().unwrap().path().unwrap(),
            b"/parent/alias"
        );
    }
}

#[test]
fn entry_invalidation_replans_namespace_copies_created_after_the_original_unhash() {
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (_paths, dir) = open_directory(&v, c, false);
    let tree = tmpfs(&mut v);
    attach(&v, tree, dir);
    let mut sibling = v.clone_with_resources(false, false);
    let admin = v.mount_admin().unwrap();
    let held = admin.enter();
    let packet = reply(0, 3, &named(1, None, b"directory", 0));
    let mut pending = prepare(&v, c, &packet).unwrap().unwrap();
    assert!(pending.take(&mut v).is_none() && !pending.ready());
    drop(held);
    sibling.unshare_mounts().unwrap();
    assert_eq!(temporary_mounts(&v).len(), 1);
    assert_eq!(temporary_mounts(&sibling).len(), 1);
    assert!(matches!(
        pending.take(&mut v),
        Some(Ok(FileValue::Count(_)))
    ));
    assert!(temporary_mounts(&v).is_empty());
    assert!(temporary_mounts(&sibling).is_empty());
    v.mkdir_at(AT_FDCWD, b"/again", 0o755).unwrap();
    assert_eq!(
        namespace(
            &v,
            NamespaceCall::MountFd(MountFdCall::Move {
                from: tree as i32,
                source: Vec::new(),
                to: AT_FDCWD,
                target: b"/again".to_vec(),
                flags: 4,
            })
        ),
        0
    );
    assert_eq!(temporary_mounts(&v).len(), 1);
    assert!(matches!(
        pending.take(&mut v),
        Some(Ok(FileValue::Count(_)))
    ));
    assert_eq!(temporary_mounts(&v).len(), 1);
}

#[test]
fn entry_notification_after_lazy_unmount_does_not_pin_the_same_retired_mount_twice() {
    let (mut v, dev) = mounted();
    let c = &dev.daemon.get().unwrap().connection;
    let (_paths, dir) = open_directory(&v, c, false);
    let tree = tmpfs(&mut v);
    attach(&v, tree, dir);
    let original = {
        let mounts = v.mounts.as_ref().unwrap().0.borrow();
        Arc::downgrade(
            mounts
                .mounts
                .iter()
                .find(|mount| mount.kind == mounts::Kind::Tmpfs)
                .unwrap(),
        )
    };
    v.umount(b"/mnt", 2).unwrap();
    let body = named(1, None, b"directory", 0);
    assert_eq!(apply(&mut v, c, 3, &body), Ok((16 + body.len()) as u64));
    v.close(tree).unwrap();
    v.close(dir).unwrap();
    for _ in 0..8 {
        let request = match c.read(8192) {
            Ok(request) => request,
            Err(Errno(11 | 19)) => break,
            Err(error) => panic!("retired close failed: {error:?}"),
        };
        match u32::from_le_bytes(request[4..8].try_into().unwrap()) {
            25 => answer(c, &request, &[]),
            2 | 29 => {}
            opcode => panic!("unexpected retired close request {opcode}"),
        }
    }
    v.reap_detached_mounts();
    assert!(
        original.upgrade().is_none(),
        "last original FD release must retire the detached mount"
    );
}
