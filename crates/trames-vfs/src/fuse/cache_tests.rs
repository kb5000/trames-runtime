// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::fuse::tests::{answer, id, mounted, open_file, receive, reply};
use trames_memory::{CgroupMemoryTarget, MemoryCgroup};

fn opened(v: &Vfs, c: &Connection) -> (SharedFd, Arc<File>) {
    let (_paths, fd) = open_file(v, c, 0);
    let original = v.shared_files().lookup(fd).unwrap().unwrap();
    let Some(events::SharedControl::FuseFile(file)) = &original.open.control else {
        panic!("FUSE OFD")
    };
    let file = file.clone();
    file.attr.lock().unwrap()[8..16].copy_from_slice(&8192u64.to_le_bytes());
    (original, file)
}
fn wave(read: &Read) -> &Arc<ReadWave> {
    let Read::Pending(read) = read else {
        panic!("pending page read")
    };
    read
}
fn completed(read: &Read) -> Arc<Page> {
    read.result().unwrap().unwrap()
}
fn contents(page: &Page) -> [u8; PAGE_SIZE as usize] {
    let mut bytes = [0; PAGE_SIZE as usize];
    page.bytes.copy_read(0, &mut bytes);
    bytes
}

#[test]
fn accepted_page_source_keeps_the_original_ofd_across_close_and_numeric_reuse() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (_, fd) = open_file(&v, c, 0);
    let target = v
        .shared_files()
        .lookup(fd)
        .unwrap()
        .unwrap()
        .file_target()
        .unwrap();
    let source = target.page_source(0).unwrap().unwrap();
    drop(target);
    let _actor =
        crate::FileActorScope::enter(Arc::new(CredentialState::new(v.credentials.clone())), v.pid);
    let Err(MemoryError::Pending(pending)) = source.load() else {
        panic!("first cold load must hand back its page wait")
    };
    let request = receive(c, 15, 10);
    v.close(fd).unwrap();
    assert_eq!(
        v.open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
            .unwrap(),
        fd
    );
    answer(c, &request, b"original");
    assert!(pending.wait.ready());
    let page = source.load().unwrap();
    let mut bytes = [0; 8];
    page.copy_read(0, &mut bytes);
    assert_eq!(&bytes, b"original");
    assert!(Arc::ptr_eq(&page, &source.load().unwrap()));
    // Closing guest membership flushes the original file even while the page
    // source keeps its OFD alive. It must not release the original handle yet.
    let flush = receive(c, 25, 10);
    assert_eq!(&flush[40..48], &9876u64.to_le_bytes());
    answer(c, &flush, &[]);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn page_reads_share_the_original_request_and_publish_short_read_zeroes() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (original, file) = opened(&v, c);
    let _actor =
        crate::FileActorScope::enter(Arc::new(CredentialState::new(v.credentials.clone())), v.pid);
    let first = file.read_page(&original, 0).unwrap();
    let follower = file.read_page(&original, 0).unwrap();
    assert!(Arc::ptr_eq(wave(&first), wave(&follower)));
    assert!(!wave(&first).wait.ready());
    let request = receive(c, 15, 10);
    assert_eq!(
        u64::from_le_bytes(request[40..48].try_into().unwrap()),
        9876
    );
    assert_eq!(
        u32::from_le_bytes(request[56..60].try_into().unwrap()),
        PAGE_SIZE as u32
    );
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "one daemon read for both actors"
    );
    answer(c, &request, b"abc");
    assert!(wave(&first).wait.ready());
    let page = completed(&first);
    assert!(Arc::ptr_eq(&page, &completed(&follower)));
    let bytes = contents(&page);
    assert_eq!(&bytes[..3], b"abc");
    assert!(bytes[3..].iter().all(|byte| *byte == 0));
    assert_eq!(
        u64::from_le_bytes(file.attr.lock().unwrap()[8..16].try_into().unwrap()),
        3
    );
    assert_eq!(
        original.open.file_position.snapshot(),
        0,
        "page IO never commits read(2)'s f_pos"
    );
    let cached = file.read_page(&original, 0).unwrap();
    assert!(matches!(cached, Read::Ready(_)));
    assert!(Arc::ptr_eq(&page, &completed(&cached)));
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn a_new_reader_can_retry_without_changing_the_original_error() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (original, file) = opened(&v, c);
    let _actor =
        crate::FileActorScope::enter(Arc::new(CredentialState::new(v.credentials.clone())), v.pid);
    let failed = file.read_page(&original, 0).unwrap();
    let request = receive(c, 15, 10);
    c.write(&reply(id(&request), -5, &[])).unwrap();
    assert!(wave(&failed).wait.ready());
    assert!(matches!(failed.result(), Some(Err(Errno(5)))));
    let retry = file.read_page(&original, 0).unwrap();
    assert!(!Arc::ptr_eq(wave(&failed), wave(&retry)));
    answer(c, &receive(c, 15, 10), &[9; PAGE_SIZE as usize]);
    assert!(contents(&completed(&retry)).iter().all(|byte| *byte == 9));
    assert!(
        matches!(failed.result(), Some(Err(Errno(5)))),
        "retry cannot consume or replace an old completion"
    );
}

#[test]
fn invalidating_an_inflight_page_cannot_publish_its_late_reply_as_current() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (original, file) = opened(&v, c);
    let _actor =
        crate::FileActorScope::enter(Arc::new(CredentialState::new(v.credentials.clone())), v.pid);
    let old = file.read_page(&original, 0).unwrap();
    let old_request = receive(c, 15, 10);
    file.attr.cache.invalidate(0, PAGE_SIZE);
    let new = file.read_page(&original, 0).unwrap();
    let new_request = receive(c, 15, 10);
    answer(c, &new_request, &[2; PAGE_SIZE as usize]);
    answer(c, &old_request, &[1; PAGE_SIZE as usize]);
    let old_page = completed(&old);
    let new_page = completed(&new);
    assert!(!Arc::ptr_eq(&old_page, &new_page));
    assert!(contents(&old_page).iter().all(|byte| *byte == 1));
    assert!(contents(&new_page).iter().all(|byte| *byte == 2));
    let current = file.read_page(&original, 0).unwrap();
    assert!(Arc::ptr_eq(&completed(&current), &new_page));
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn dropping_one_reader_keeps_the_shared_request_and_last_drop_cancels_it() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (original, file) = opened(&v, c);
    let _actor =
        crate::FileActorScope::enter(Arc::new(CredentialState::new(v.credentials.clone())), v.pid);
    let first = file.read_page(&original, 0).unwrap();
    let follower = file.read_page(&original, 0).unwrap();
    let weak = Arc::downgrade(wave(&first));
    drop(first);
    assert!(weak.upgrade().is_some());
    drop(follower);
    assert!(weak.upgrade().is_none());
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "unread request withdrawn with its final resource owner"
    );
    let retry = file.read_page(&original, 0).unwrap();
    answer(c, &receive(c, 15, 10), &[3; PAGE_SIZE as usize]);
    assert!(contents(&completed(&retry)).iter().all(|byte| *byte == 3));
}

#[test]
fn physical_cache_is_charged_to_the_reader_not_the_replying_daemon() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (original, file) = opened(&v, c);
    let _actor =
        crate::FileActorScope::enter(Arc::new(CredentialState::new(v.credentials.clone())), v.pid);
    let reader = MemoryCgroup::new(None);
    let daemon = MemoryCgroup::new(None);
    reader.set_limit(PAGE_SIZE as usize);
    daemon.set_limit(0);
    let target = Arc::new(CgroupMemoryTarget::default());
    let _scope = target.scope();
    target.set(Some(reader.clone()));
    let read = file.read_page(&original, 0).unwrap();
    assert_eq!(reader.current(), PAGE_SIZE as usize);
    target.set(Some(daemon.clone()));
    answer(c, &receive(c, 15, 10), &[5; PAGE_SIZE as usize]);
    let page = completed(&read);
    assert_eq!(daemon.current(), 0);
    let alias = file.read_page(&original, 0).unwrap();
    assert!(Arc::ptr_eq(&page, &completed(&alias)));
    assert!(matches!(
        file.read_page(&original, 1),
        Err(MemoryError::Limit)
    ));
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "quota failure publishes no daemon IO"
    );
    file.attr.cache.invalidate(0, PAGE_SIZE);
    assert_eq!(
        reader.current(),
        PAGE_SIZE as usize,
        "original readers still retain their physical page"
    );
    drop((page, read, alias));
    assert_eq!(reader.current(), 0);
}

#[test]
fn a_later_attribute_or_active_writer_prevents_short_read_size_rollback() {
    for newer in [false, true] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let (original, file) = opened(&v, c);
        let _actor = crate::FileActorScope::enter(
            Arc::new(CredentialState::new(v.credentials.clone())),
            v.pid,
        );
        let read = file.read_page(&original, 0).unwrap();
        let request = receive(c, 15, 10);
        let writer = if newer {
            file.attr.lock().unwrap().version = file.reference.fs.connection.next_attr_version();
            None
        } else {
            Some(file.attr.try_write().unwrap())
        };
        answer(c, &request, b"x");
        assert_eq!(contents(&completed(&read))[0], b'x');
        assert_eq!(
            u64::from_le_bytes(file.attr.lock().unwrap()[8..16].try_into().unwrap()),
            8192
        );
        drop(writer);
    }
}

fn invalidate(c: &Connection, inode: u64, offset: i64, length: i64) -> Result<usize> {
    let mut body = [0; 24];
    body[..8].copy_from_slice(&inode.to_le_bytes());
    body[8..16].copy_from_slice(&offset.to_le_bytes());
    body[16..24].copy_from_slice(&length.to_le_bytes());
    c.write(&reply(0, 2, &body))
}

#[test]
fn inode_notification_invalidates_data_and_guards_against_older_short_reads() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (original, file) = opened(&v, c);
    let _actor =
        crate::FileActorScope::enter(Arc::new(CredentialState::new(v.credentials.clone())), v.pid);
    let old = file.read_page(&original, 0).unwrap();
    let request = receive(c, 15, 10);
    assert_eq!(invalidate(c, 10, 0, 0), Ok(40));
    let current = file.read_page(&original, 0).unwrap();
    answer(c, &receive(c, 15, 10), &[4; PAGE_SIZE as usize]);
    answer(c, &request, b"old");
    assert_eq!(&contents(&completed(&old))[..3], b"old");
    assert_eq!(
        u64::from_le_bytes(file.attr.lock().unwrap()[8..16].try_into().unwrap()),
        8192,
        "notification's version prevents delayed EOF from shrinking the current inode"
    );
    assert!(Arc::ptr_eq(
        &completed(&current),
        &completed(&file.read_page(&original, 0).unwrap())
    ));
    // A negative offset invalidates attributes/ACLs alone.
    assert_eq!(invalidate(c, 10, -1, 0), Ok(40));
    assert!(matches!(
        file.read_page(&original, 0).unwrap(),
        Read::Ready(_)
    ));
    // A negative length invalidates every cached page from the offset onward.
    assert_eq!(invalidate(c, 10, 0, -1), Ok(40));
    let again = file.read_page(&original, 0).unwrap();
    assert!(matches!(again, Read::Pending(_)));
    drop(again);
}

#[test]
fn malformed_unknown_and_missing_inode_notifications_leave_original_reads_intact() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (original, file) = opened(&v, c);
    let _actor =
        crate::FileActorScope::enter(Arc::new(CredentialState::new(v.credentials.clone())), v.pid);
    let read = file.read_page(&original, 0).unwrap();
    let request = receive(c, 15, 10);
    for length in [0, 23, 25] {
        assert_eq!(c.write(&reply(0, 2, &vec![0; length])), Err(Errno(22)));
    }
    assert_eq!(c.write(&reply(0, 200, &[])), Err(Errno(22)));
    assert_eq!(invalidate(c, 999, 0, 0), Err(Errno(2)));
    assert!(!wave(&read).wait.ready());
    answer(c, &request, &[7; PAGE_SIZE as usize]);
    assert!(contents(&completed(&read)).iter().all(|byte| *byte == 7));
}

#[test]
fn page_io_uses_live_fs_credentials_and_the_original_connection_pid_namespace() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (original, file) = opened(&v, c);
    v.unshare_pid().unwrap();
    v.activate_child_pid(42).unwrap();
    v.set_process_context(42);
    assert_eq!(v.pid_namespace().local(42), 1);
    assert_eq!(file.reference.fs.caller(&v).pid, 42);
    let credentials = Arc::new(CredentialState::new(v.credentials.clone()));
    let _actor = crate::FileActorScope::enter(credentials.clone(), 42);
    let mut changed = credentials.read().clone();
    changed.fsuid = 1234;
    changed.fsgid = 2345;
    credentials.publish(&changed);
    let read = file.read_page(&original, 0).unwrap();
    let request = receive(c, 15, 10);
    assert_eq!(
        u32::from_le_bytes(request[24..28].try_into().unwrap()),
        1234
    );
    assert_eq!(
        u32::from_le_bytes(request[28..32].try_into().unwrap()),
        2345
    );
    assert_eq!(u32::from_le_bytes(request[32..36].try_into().unwrap()), 42);
    answer(c, &request, &[8; PAGE_SIZE as usize]);
    assert_eq!(contents(&completed(&read))[0], 8);
}

#[test]
fn the_last_signed_file_page_does_not_read_past_maxbytes() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (original, file) = opened(&v, c);
    let _actor =
        crate::FileActorScope::enter(Arc::new(CredentialState::new(v.credentials.clone())), v.pid);
    let read = file
        .read_page(&original, i64::MAX as u64 / PAGE_SIZE)
        .unwrap();
    let request = receive(c, 15, 10);
    assert_eq!(
        u32::from_le_bytes(request[56..60].try_into().unwrap()),
        PAGE_SIZE as u32 - 1
    );
    answer(c, &request, &vec![6; PAGE_SIZE as usize - 1]);
    let bytes = contents(&completed(&read));
    assert!(bytes[..PAGE_SIZE as usize - 1]
        .iter()
        .all(|byte| *byte == 6));
    assert_eq!(bytes[PAGE_SIZE as usize - 1], 0);
}
