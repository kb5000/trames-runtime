// SPDX-License-Identifier: GPL-3.0-or-later
//! Native copy-up resumes original data and open publication through IO waits.
use super::*;

struct Store(std::path::PathBuf);
impl Store {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "trames-copy-up-origin-{}-{}",
            std::process::id(),
            trames_memory::new_backing_identity()
        )))
    }
}
impl Drop for Store {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn write(v: &mut Vfs, path: &[u8], bytes: &[u8]) {
    let fd = v.open_at(AT_FDCWD, path, 2, 0).unwrap();
    assert_eq!(v.write(fd, bytes).unwrap(), bytes.len());
    v.close(fd).unwrap();
}
fn stat(v: &mut Vfs, group: &str, field: &str) -> u64 {
    let path = format!("/sys/fs/cgroup/{group}/io.stat");
    let fd = v.open_at(AT_FDCWD, path.as_bytes(), 0, 0).unwrap();
    let bytes = v.pread(fd, 4096, 0).unwrap();
    v.close(fd).unwrap();
    String::from_utf8(bytes)
        .unwrap()
        .split_whitespace()
        .find_map(|part| part.strip_prefix(field).map(|value| value.parse().unwrap()))
        .unwrap_or(0)
}
fn fixture(store: &Store, length: usize) -> (Vfs, Vec<u8>, Arc<Overlay>, NodeRef) {
    let mut v = Vfs::open_disk(&store.0, Default::default()).unwrap();
    v.set_runtime_info(1, Default::default());
    for path in [b"/lower".as_slice(), b"/upper", b"/work", b"/merged"] {
        v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
    }
    let original: Vec<_> = (0..length)
        .map(|offset| (offset / 4096 + 1) as u8)
        .collect();
    v.import_file(b"/lower/file", original.clone()).unwrap();
    v.chmod_at(AT_FDCWD, b"/lower/file", 0o666).unwrap();
    v.mount(
        Some(b"overlay"),
        b"/merged",
        Some(b"overlay"),
        0,
        Some(b"lowerdir=/lower,upperdir=/upper,workdir=/work,index=off"),
    )
    .unwrap();
    let fs = v.mount_location(b"/merged", true).unwrap().filesystem(&v);
    let (overlay, node) = {
        let fs = fs.borrow();
        (
            fs.overlay.as_ref().unwrap().clone(),
            fs.paths[b"/file".as_slice()].clone(),
        )
    };
    write(
        &mut v,
        b"/sys/fs/cgroup/cgroup.subtree_control",
        b"+memory +io",
    );
    for path in [b"/sys/fs/cgroup/a".as_slice(), b"/sys/fs/cgroup/b"] {
        v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
    }
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    (v, original, overlay, node)
}
fn accepted(v: &Vfs, flags: u32) -> FileWork {
    let mut epoch = FileEpoch::default();
    let files = epoch.capture(v, true);
    let paths = v.path_queries();
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/merged/file", flags, 0, 0, &files)
        .is_none());
    let work = paths
        .take_open_work()
        .expect("original overlay open and FD reservation");
    assert!(work.waiting());
    assert!(!work.ready());
    work
}
fn finished(work: FileWork) -> u32 {
    let mut outcome = work.run();
    for _ in 0..4 {
        outcome = match outcome {
            FileOutcome::Complete(reply) => {
                let FileValue::Count(fd) = reply.result.unwrap() else {
                    panic!("published FD")
                };
                return fd as u32;
            }
            FileOutcome::Layout(work) => {
                let admission = work.begin_layout().unwrap().try_enter().ok().unwrap();
                work.enter_layout(admission).run()
            }
            FileOutcome::Waiting(work) if work.ready() => work.run(),
            _ => panic!("original open completion"),
        };
    }
    panic!("bounded original open stages")
}
fn next_slot(v: &mut Vfs) -> u32 {
    let fd = v.open_at(AT_FDCWD, b"/lower/file", 0, 0).unwrap();
    v.close(fd).unwrap();
    fd
}

#[test]
fn copy_up_read_wait_keeps_the_copied_prefix_after_reclaim_and_lower_name_or_fd_reuse() {
    let store = Store::new();
    let (mut v, original, overlay, node) = fixture(&store, 12288);
    let lower = v.open_at(AT_FDCWD, b"/lower/file", 2, 0).unwrap();
    let old = v.dup(lower, 0, false).unwrap();
    let slot = next_slot(&mut v);
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=1");
    let task = v.cgroup_task(1).unwrap();
    let scope = task.resource_scope();
    let before = v.fds.entries().len();
    let work = accepted(&v, 2);
    assert_eq!(v.fds.entries().len(), before);
    assert_eq!(v.flags(slot), Err(Errno(9)));
    assert!(overlay.uncopied_inode(&node));
    assert_eq!(stat(&mut v, "a", "rios="), 1);
    assert_eq!(stat(&mut v, "a", "wios="), 0);
    drop(scope);
    v.pwrite(lower, &[99], 0).unwrap();
    v.rename_at(AT_FDCWD, b"/lower/file", AT_FDCWD, b"/lower/original", 0)
        .unwrap();
    v.close(lower).unwrap();
    v.import_file(b"/lower/file", vec![8; 12288]).unwrap();
    assert_eq!(v.open_at(AT_FDCWD, b"/lower/file", 2, 0).unwrap(), lower);
    write(&mut v, b"/sys/fs/cgroup/a/memory.reclaim", b"4096");
    write(&mut v, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=max");
    let resources = task.resource_context();
    let fd = std::thread::spawn(move || {
        let _other = resources.enter();
        finished(work)
    })
    .join()
    .unwrap();
    assert_eq!(fd, slot);
    assert!(!overlay.uncopied_inode(&node));
    assert_eq!(stat(&mut v, "a", "rios="), 3);
    assert_eq!(stat(&mut v, "a", "wios="), 2);
    assert_eq!(stat(&mut v, "b", "rios="), 0);
    assert_eq!(stat(&mut v, "b", "wios="), 0);
    assert_eq!(v.pread(fd, 12288, 0).unwrap(), original);
    assert_eq!(v.pread(old, 1, 0).unwrap(), vec![99]);
    assert_eq!(v.pread(lower, 1, 0).unwrap(), vec![8]);
}

#[test]
fn copy_up_write_wait_keeps_both_buffers_and_cancel_refunds_only_the_unpublished_provider() {
    for cancel in [false, true] {
        let store = Store::new();
        let (mut v, original, overlay, node) = fixture(&store, 131072);
        let slot = next_slot(&mut v);
        let baseline = v.capacity().used_bytes;
        write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=1");
        let task = v.cgroup_task(1).unwrap();
        let scope = task.resource_scope();
        let work = accepted(&v, 2);
        let held = overlay
            .copying
            .borrow()
            .get(&pointer(&node))
            .unwrap()
            .clone();
        assert!(held.upgrade().is_some());
        assert_eq!(stat(&mut v, "a", "rios="), 32);
        assert_eq!(stat(&mut v, "a", "wios="), 1);
        assert_eq!(v.capacity().used_bytes, baseline + 65536);
        drop(scope);
        let lower = v.open_at(AT_FDCWD, b"/lower/file", 2, 0).unwrap();
        v.pwrite(lower, &[99], 0).unwrap();
        v.pwrite(lower, &[99], 65536).unwrap();
        v.close(lower).unwrap();
        write(&mut v, b"/sys/fs/cgroup/a/memory.reclaim", b"131072");
        write(&mut v, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
        let _other = task.resource_scope();
        if cancel {
            drop(work);
            assert!(held.upgrade().is_none());
            assert!(overlay.uncopied_inode(&node));
            assert_eq!(v.capacity().used_bytes, baseline);
            assert_eq!(v.open_at(AT_FDCWD, b"/lower/file", 0, 0).unwrap(), slot);
            assert_eq!(stat(&mut v, "a", "wios="), 1);
        } else {
            write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=max");
            let fd = finished(work);
            assert_eq!(fd, slot);
            assert!(held.upgrade().is_none());
            assert_eq!(stat(&mut v, "a", "rios="), 32);
            assert_eq!(stat(&mut v, "a", "wios="), 3);
            assert_eq!(stat(&mut v, "b", "wios="), 0);
            assert_eq!(v.pread(fd, original.len(), 0).unwrap(), original);
        }
    }
}

#[test]
fn an_open_waiting_after_copy_up_keeps_its_inode_and_fd_slot_across_merged_path_replacement() {
    for truncate in [false, true] {
        let store = Store::new();
        let (mut v, original, overlay, node) = fixture(&store, 12288);
        let slot = next_slot(&mut v);
        write(
            &mut v,
            b"/sys/fs/cgroup/a/io.max",
            if truncate {
                b"253:1 wbps=1"
            } else {
                b"253:1 wiops=1"
            },
        );
        let task = v.cgroup_task(1).unwrap();
        let scope = task.resource_scope();
        let work = accepted(&v, if truncate { 2 | O_TRUNC } else { 2 });
        assert!(!overlay.uncopied_inode(&node));
        assert_eq!(v.flags(slot), Err(Errno(9)));
        drop(scope);
        v.rename_at(AT_FDCWD, b"/merged/file", AT_FDCWD, b"/merged/moved", 0)
            .unwrap();
        let replacement = v.open_at(AT_FDCWD, b"/merged/file", 0x42, 0o600).unwrap();
        v.write(replacement, b"replacement").unwrap();
        write(&mut v, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
        write(
            &mut v,
            b"/sys/fs/cgroup/a/io.max",
            b"253:1 wbps=max wiops=max",
        );
        let _other = task.resource_scope();
        let fd = finished(work);
        assert_eq!(fd, slot);
        assert_eq!(
            v.pread(fd, original.len(), 0).unwrap(),
            if truncate { Vec::new() } else { original }
        );
        assert_eq!(v.pread(replacement, 20, 0).unwrap(), b"replacement");
        assert!(Arc::ptr_eq(
            v.descriptor(fd)
                .unwrap()
                .open
                .borrow()
                .node
                .as_ref()
                .unwrap(),
            &node
        ));
    }
}

#[test]
fn another_accepted_open_can_finish_the_shared_copy_after_the_first_waiter_cancels() {
    let store = Store::new();
    let (mut v, original, overlay, node) = fixture(&store, 12288);
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=1");
    let task = v.cgroup_task(1).unwrap();
    let scope = task.resource_scope();
    let first = accepted(&v, 2);
    let held = overlay
        .copying
        .borrow()
        .get(&pointer(&node))
        .unwrap()
        .clone();
    write(&mut v, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
    drop(scope);
    let _other = task.resource_scope();
    let second = accepted(&v, 2);
    drop(first);
    assert!(held.upgrade().is_some());
    assert_eq!(stat(&mut v, "a", "rios="), 1);
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=max");
    let fd = finished(second);
    assert!(held.upgrade().is_none());
    assert_eq!(stat(&mut v, "a", "rios="), 3);
    assert_eq!(stat(&mut v, "a", "wios="), 1);
    // The second call writes the final manifest after the shared data work
    // restored its original owner and returned to this caller's own scope.
    assert_eq!(stat(&mut v, "b", "wios="), 1);
    assert_eq!(v.pread(fd, original.len(), 0).unwrap(), original);
}

#[test]
fn copy_up_keeps_completed_data_and_capability_stages_across_separate_budget_waves() {
    let store = Store::new();
    let (mut v, original, overlay, node) = fixture(&store, 12288);
    let mut caps = vec![0; 20];
    caps[..4].copy_from_slice(&0x0200_0001u32.to_le_bytes());
    caps[4..8].copy_from_slice(&(1u32 << capabilities::SETUID).to_le_bytes());
    v.set_xattr(
        AT_FDCWD,
        Some(b"/lower/file"),
        true,
        file_caps::NAME,
        Some(&caps),
        0,
    )
    .unwrap();
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=1");
    let task = v.cgroup_task(1).unwrap();
    let _scope = task.resource_scope();
    let work = accepted(&v, 2);
    assert!(overlay.uncopied_inode(&node));
    assert_eq!(stat(&mut v, "a", "wios="), 1);
    assert_eq!(stat(&mut v, "a", "wbytes="), original.len() as u64);
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=max");
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=1");
    let FileOutcome::Waiting(work) = work.run() else {
        panic!("the manifest needs its own credit")
    };
    assert!(!work.ready());
    assert!(!overlay.uncopied_inode(&node));
    assert_eq!(stat(&mut v, "a", "wios="), 2);
    assert_eq!(
        v.get_xattr(AT_FDCWD, Some(b"/merged/file"), true, file_caps::NAME)
            .unwrap(),
        caps
    );
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=max");
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=1");
    let fd = finished(work);
    assert_eq!(stat(&mut v, "a", "rios="), 3);
    assert_eq!(stat(&mut v, "a", "wios="), 3);
    assert_eq!(
        stat(&mut v, "a", "wbytes="),
        original.len() as u64
            + caps.len() as u64
            + std::fs::metadata(store.0.join("manifest")).unwrap().len()
    );
    assert_eq!(v.pread(fd, original.len(), 0).unwrap(), original);
}

#[test]
fn an_accepted_open_keeps_its_access_grant_when_permissions_change_during_copy_up() {
    let store = Store::new();
    let (mut v, original, _, _) = fixture(&store, 12288);
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=1");
    let task = v.cgroup_task(1).unwrap();
    let scope = task.resource_scope();
    let paths = v.path_queries();
    paths.view.borrow_mut().credentials = Credentials::user(1000, 1000);
    let mut epoch = FileEpoch::default();
    let files = epoch.capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/merged/file", 2, 0, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    assert!(!work.ready());
    drop(scope);
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=max");
    // This independent root operation completes the common data copy while
    // changing permissions. The first call already passed its open checks.
    v.chmod_at(AT_FDCWD, b"/merged/file", 0).unwrap();
    let fd = finished(work);
    assert_eq!(v.pread(fd, original.len(), 0).unwrap(), original);
    assert_eq!(
        paths.open_at_resolve(AT_FDCWD, b"/merged/file", 2, 0, 0, &files),
        Some(Err(Errno(13)))
    );
}
