// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{
    CgroupMemoryKind, CgroupMemoryTarget, CgroupPageCharge, CgroupReclaim, MemoryCgroup, PageWait,
    PAGE_SIZE,
};

fn write(v: &mut Vfs, path: &[u8], bytes: &[u8]) {
    let fd = v.open_at(AT_FDCWD, path, 2, 0).unwrap();
    assert_eq!(v.write(fd, bytes).unwrap(), bytes.len());
    v.close(fd).unwrap();
}
fn setup() -> (Vfs, Arc<MemoryCgroup>) {
    let mut v = Vfs::default();
    v.set_runtime_info(1, Default::default());
    write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"+memory");
    v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/a", 0o755).unwrap();
    let memory = v
        .cgroups
        .borrow()
        .groups
        .values()
        .find_map(|group| group.memory.clone())
        .unwrap();
    (v, memory)
}
#[derive(Default)]
struct Held {
    wait: Arc<PageWait>,
    submissions: AtomicU32,
}
impl CgroupReclaim for Held {
    fn reclaim(&self, _: &MemoryCgroup, _: usize) -> usize {
        0
    }
    fn writeback(&self, _: &Arc<MemoryCgroup>, _: usize) -> Option<Arc<PageWait>> {
        if self.wait.ready() {
            return None;
        }
        self.submissions.fetch_add(1, Ordering::Relaxed);
        Some(self.wait.clone())
    }
}
fn allocation(group: &Arc<MemoryCgroup>, held: &Arc<Held>) -> CgroupPageCharge {
    let target = Arc::new(CgroupMemoryTarget::default());
    target.set(Some(group.clone()));
    let _scope = target.scope();
    let page = CgroupPageCharge::new(CgroupMemoryKind::Anonymous).unwrap();
    page.register_reclaimer(&(held.clone() as Arc<dyn CgroupReclaim>));
    page
}
fn work(v: &Vfs, fd: u32, bytes: &[u8]) -> FileWork {
    FileWork::new(
        &v.path_queries(),
        v.shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .filesystem_target(),
        FileCommand::Write {
            bytes: bytes.to_vec(),
            offset: None,
        },
    )
}
fn waiting(work: FileWork) -> FileWork {
    match work.run() {
        FileOutcome::Waiting(work) => work,
        _ => panic!("retained controller pressure"),
    }
}
#[test]
fn nonblocking_limit_writes_skip_reclaim_on_both_vfs_and_shared_byte_interfaces() {
    let (mut v, group) = setup();
    let held = Arc::new(Held::default());
    let _allocation = allocation(&group, &held);
    let fd = v
        .open_at(AT_FDCWD, b"/sys/fs/cgroup/a/memory.max", 2 | O_NONBLOCK, 0)
        .unwrap();
    assert_eq!(v.write(fd, b"0"), Ok(1));
    assert_eq!(group.limit(), 0);
    let high = v
        .open_at(AT_FDCWD, b"/sys/fs/cgroup/a/memory.high", 2 | O_NONBLOCK, 0)
        .unwrap();
    assert_eq!(v.direct_descriptors().get(high).unwrap().write(b"0"), Ok(1));
    assert_eq!(group.high(), 0);
    assert_eq!(held.submissions.load(Ordering::Relaxed), 0);
    assert_eq!(group.current(), PAGE_SIZE as usize);
}
#[test]
fn another_limit_writer_wakes_original_request_without_replaying_its_configuration_or_fd() {
    let (mut v, group) = setup();
    let held = Arc::new(Held::default());
    let _allocation = allocation(&group, &held);
    let fd = v
        .open_at(AT_FDCWD, b"/sys/fs/cgroup/a/memory.max", 2, 0)
        .unwrap();
    let original = v.shared_files().lookup(fd).unwrap().unwrap();
    let pending = waiting(work(&v, fd, b"0"));
    assert!(!pending.ready());
    assert_eq!(original.open.file_position.lock().unwrap().pending, 1);
    let alias = v
        .open_at(AT_FDCWD, b"/sys/fs/cgroup/a/memory.max", 2 | O_NONBLOCK, 0)
        .unwrap();
    v.write(alias, b"8192").unwrap();
    assert!(pending.ready());
    v.close(fd).unwrap();
    let reused = v
        .open_at(AT_FDCWD, b"/sys/fs/cgroup/a/memory.high", 2 | O_NONBLOCK, 0)
        .unwrap();
    assert_eq!(reused, fd);
    let FileOutcome::Complete(reply) = pending.run() else {
        panic!("superseded reclaim completes")
    };
    assert!(matches!(reply.result, Ok(FileValue::Count(1))));
    assert_eq!(group.limit(), 8192);
    assert_eq!(original.open.file_position.snapshot(), 1);
    assert_eq!(v.seek(reused, 0, 1), Ok(0));
    assert!(
        !held.wait.ready(),
        "configuration wake does not invent writeback completion"
    );
}
#[test]
fn cancelling_a_tightening_keeps_its_applied_limit_and_releases_the_original_position() {
    let (mut v, group) = setup();
    let held = Arc::new(Held::default());
    let _allocation = allocation(&group, &held);
    let fd = v
        .open_at(AT_FDCWD, b"/sys/fs/cgroup/a/memory.max", 2, 0)
        .unwrap();
    let original = v.shared_files().lookup(fd).unwrap().unwrap();
    let pending = waiting(work(&v, fd, b"0"));
    drop(pending);
    assert_eq!(group.limit(), 0);
    assert_eq!(original.open.file_position.lock().unwrap().pending, 0);
    assert_eq!(original.open.file_position.snapshot(), 0);
    held.wait.finish();
    let reclaim = v
        .open_at(AT_FDCWD, b"/sys/fs/cgroup/a/memory.reclaim", 2, 0)
        .unwrap();
    assert_eq!(
        v.write(reclaim, b"4096"),
        Err(Errno(11)),
        "live anonymous bytes have no swap backing"
    );
    assert_eq!(group.current(), PAGE_SIZE as usize);
}
#[test]
fn memory_events_notify_live_poll_and_later_inotify_watches_without_an_inode_borrow() {
    let (mut v, group) = setup();
    let events = v
        .open_at(AT_FDCWD, b"/sys/fs/cgroup/a/memory.events", 0, 0)
        .unwrap();
    v.pread(events, 4096, 0).unwrap();
    assert_eq!(v.poll(events, 2), 0);
    let watch = v.inotify_init(O_NONBLOCK).unwrap();
    v.inotify_add(watch, b"/sys/fs/cgroup/a/memory.events", inotify::MODIFY)
        .unwrap();
    let descriptor = v.descriptor(events).unwrap();
    let node = descriptor.open.borrow().node.clone().unwrap();
    let node_guard = node.borrow_mut();
    group.record_oom();
    drop(node_guard);
    assert_eq!(v.poll(events, 2), 10);
    assert!(!v.read(watch, 4096).unwrap().is_empty());
    assert!(String::from_utf8(v.pread(events, 4096, 0).unwrap())
        .unwrap()
        .contains("oom 1\n"));
    assert_eq!(v.poll(events, 2), 0);
}
#[test]
fn tightening_from_outside_waits_for_original_victims_and_preserves_oom_protected_tasks() {
    struct Probe(AtomicU32);
    impl TaskSignal for Probe {
        fn raise(&self, signal: u32) {
            assert_eq!(signal, 9);
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let (mut v, group) = setup();
    v.cgroup_fork(1, 2, 2);
    v.cgroup_fork(1, 3, 3);
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"2");
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"3");
    write(&mut v, b"/sys/fs/cgroup/a/memory.oom.group", b"1");
    let protected = Arc::new(OomTask::default());
    let second = v.cgroup_task(2).unwrap();
    let third = v.cgroup_task(3).unwrap();
    third.bind_oom(&protected);
    v.set_runtime_info(
        1,
        RuntimeInfo {
            processes: vec![ProcessInfo {
                pid: 3,
                tgid: 3,
                oom: Arc::downgrade(&protected),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    write(&mut v, b"/proc/3/oom_score_adj", b"-1000");
    let victim = Arc::new(Probe(AtomicU32::new(0)));
    let safe = Arc::new(Probe(AtomicU32::new(0)));
    second.bind(&(victim.clone() as Arc<dyn TaskSignal>));
    third.bind(&(safe.clone() as Arc<dyn TaskSignal>));
    let page = {
        let _scope = second.resource_scope();
        CgroupPageCharge::new(CgroupMemoryKind::Anonymous).unwrap()
    };
    let fd = v
        .open_at(AT_FDCWD, b"/sys/fs/cgroup/a/memory.max", 2, 0)
        .unwrap();
    let pending = waiting(work(&v, fd, b"0"));
    assert_eq!(victim.0.load(Ordering::Relaxed), 1);
    assert_eq!(safe.0.load(Ordering::Relaxed), 0);
    assert!(!pending.ready());
    second.exit();
    drop(page);
    assert!(pending.ready());
    let FileOutcome::Complete(reply) = pending.run() else {
        panic!("tightened group drained")
    };
    assert!(matches!(reply.result, Ok(FileValue::Count(1))));
    assert_eq!(group.current(), 0);
    assert!(group.format_events(false).contains("oom_kill 1\n"));
    assert!(v.cgroup_task(1).is_some() && v.cgroup_task(3).is_some());
}
