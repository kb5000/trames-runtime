// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn finish(paths: &PathQueries, call: NamespaceCall) -> Result<u64> {
    let result = match paths.namespace_attempt(call) {
        NamespaceAttempt::Complete(result) => result,
        NamespaceAttempt::Retained(work) => match work.run() {
            FileOutcome::Complete(reply) => reply.result,
            _ => panic!("uncontended mount operation must complete without its owner"),
        },
    }?;
    let FileValue::Count(count) = result else {
        panic!("unexpected output")
    };
    Ok(count)
}
fn mount(target: &[u8], source: Option<&[u8]>, flags: u64) -> NamespaceCall {
    NamespaceCall::Mount {
        source: source.map(<[u8]>::to_vec),
        target: target.to_vec(),
        kind: Some(b"tmpfs".to_vec()),
        flags,
        data: None,
    }
}
fn unmount(target: &[u8], flags: u64) -> NamespaceCall {
    NamespaceCall::Umount {
        target: target.to_vec(),
        flags,
    }
}
fn setup() -> Vfs {
    fn shared<T: Send + Sync>() {}
    shared::<Mount>();
    shared::<MountNamespace>();
    let mut v = Vfs::default();
    for name in [b"/a".as_slice(), b"/b", b"/c"] {
        v.mkdir_at(AT_FDCWD, name, 0o755).unwrap();
    }
    v
}

#[test]
fn detached_directory_is_not_mutable_namespace_root_authority() {
    let mut owner = setup();
    owner.mount(None, b"/a", Some(b"tmpfs"), 0, None).unwrap();
    owner.mkdir_at(AT_FDCWD, b"/a/old", 0o755).unwrap();
    let dir = owner.open_at(AT_FDCWD, b"/a", O_DIRECTORY, 0).unwrap();
    let root = owner.stat_at(AT_FDCWD, b"/").unwrap();
    owner.umount(b"/a", 2).unwrap();
    owner.chdir_fd(dir).unwrap();
    assert_eq!(
        finish(
            &owner.path_queries(),
            NamespaceCall::PivotRoot {
                new_root: b".".to_vec(),
                put_old: b"old".to_vec(),
            }
        ),
        Err(Errno(22))
    );
    assert_eq!(owner.stat_at(AT_FDCWD, b"/").unwrap(), root);
    assert!(owner.stat_at(dir as i32, b"old").is_ok());
}

#[test]
fn captured_workers_see_original_mount_move_remount_and_unmount_without_recapture() {
    let owner = setup();
    let source = owner.path_queries();
    let observer = owner.path_queries();
    let old = owner.stat_at(AT_FDCWD, b"/a").unwrap();
    assert_eq!(finish(&source, mount(b"/a", None, 0)), Ok(0));
    assert_ne!(
        observer.view.borrow().stat_at(AT_FDCWD, b"/a").unwrap()[..8],
        old[..8]
    );
    std::thread::spawn(move || {
        assert_eq!(finish(&source, mount(b"/b", Some(b"/a"), 8192)), Ok(0));
        assert_eq!(finish(&source, mount(b"/b", None, 32 | MS_RDONLY)), Ok(0));
    })
    .join()
    .unwrap();
    assert_eq!(owner.stat_at(AT_FDCWD, b"/a").unwrap(), old);
    assert_ne!(
        observer.view.borrow().stat_at(AT_FDCWD, b"/b").unwrap()[..8],
        old[..8]
    );
    assert_eq!(
        finish(
            &observer,
            NamespaceCall::Mkdir {
                fd: AT_FDCWD,
                path: b"/b/no".to_vec(),
                mode: 0o755,
            }
        ),
        Err(Errno(30))
    );
    assert_eq!(finish(&observer, mount(b"/b", None, 32)), Ok(0));
    assert_eq!(finish(&observer, mount(b"/c", Some(b"/b"), 4096)), Ok(0));
    assert_eq!(finish(&observer, unmount(b"/b", 0)), Ok(0));
    assert_eq!(finish(&observer, unmount(b"/c", 0)), Ok(0));
}

#[test]
fn pivot_replaces_original_fs_contexts_but_preserves_subdirectories_and_open_fds() {
    let mut owner = setup();
    owner.mount(None, b"/a", Some(b"tmpfs"), 0, None).unwrap();
    owner.mkdir_at(AT_FDCWD, b"/a/old", 0o755).unwrap();
    let mut peer = owner.clone();
    let mut shared = owner.clone_with_resources(false, true);
    let mut subdir = owner.clone();
    subdir.chdir(b"/b").unwrap();
    let mut other_ns = owner.clone();
    other_ns.unshare_mounts().unwrap();
    let other_root = other_ns.stat_at(AT_FDCWD, b"/").unwrap();
    let old_fd = peer.open_at(AT_FDCWD, b"/", O_DIRECTORY, 0).unwrap();
    let original = peer.stat_fd(old_fd).unwrap();
    let worker = owner.path_queries();
    let observer = peer.path_queries();
    let new = owner.stat_at(AT_FDCWD, b"/a").unwrap();
    std::thread::spawn(move || {
        assert_eq!(
            finish(
                &worker,
                NamespaceCall::PivotRoot {
                    new_root: b"/a".to_vec(),
                    put_old: b"/a/old".to_vec(),
                }
            ),
            Ok(0)
        );
    })
    .join()
    .unwrap();
    for v in [&owner, &peer, &shared] {
        assert_eq!(v.stat_at(AT_FDCWD, b"/").unwrap()[..8], new[..8]);
        assert_eq!(v.cwd().unwrap(), b"/");
    }
    assert_eq!(
        observer.view.borrow().stat_at(AT_FDCWD, b"/").unwrap()[..8],
        new[..8]
    );
    assert_eq!(subdir.cwd().unwrap(), b"/old/b");
    assert_eq!(peer.stat_fd(old_fd).unwrap(), original);
    assert_eq!(other_ns.stat_at(AT_FDCWD, b"/").unwrap(), other_root);
    // A retained descriptor does not adopt pivot's replacement fs_struct path.
    peer.chdir_fd(old_fd).unwrap();
    assert_eq!(peer.cwd().unwrap(), b"/old");
    shared.chdir(b"/old/b").unwrap();
    assert_eq!(owner.cwd().unwrap(), b"/old/b");
}

#[test]
fn busy_namespace_waits_on_original_resource_and_cancellation_has_no_effects() {
    use std::sync::atomic::AtomicUsize;
    struct Wake(AtomicUsize);
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let owner = setup();
    let mut other = owner.clone();
    other.unshare_mounts().unwrap();
    let worker = owner.path_queries();
    let admin = owner.mount_admin().unwrap();
    let lease = admin.enter();
    let NamespaceAttempt::Retained(work) = worker.namespace_attempt(mount(b"/a", None, 0)) else {
        panic!("busy original namespace must return its execution slot")
    };
    assert!(work.waiting());
    assert!(!work.ready());
    let wake = Arc::new(Wake(AtomicUsize::new(0)));
    let target: Arc<dyn IoWake> = wake.clone();
    let signal = IoSignal::new(1, Arc::downgrade(&target));
    let subscription = work.wait_sources(&signal).unwrap();
    // A different namespace is independent even though its backing is shared.
    assert_eq!(finish(&other.path_queries(), mount(b"/a", None, 0)), Ok(0));
    drop(lease);
    assert!(work.ready());
    assert!(wake.0.load(Ordering::Relaxed) > 0);
    let FileOutcome::Complete(reply) = work.run() else {
        panic!("ready namespace")
    };
    assert!(matches!(reply.result, Ok(FileValue::Count(0))));
    drop(subscription);
    let lease = admin.enter();
    let NamespaceAttempt::Retained(cancelled) = worker.namespace_attempt(unmount(b"/a", 0)) else {
        panic!("busy original namespace")
    };
    drop(cancelled);
    drop(lease);
    assert_ne!(
        owner.stat_at(AT_FDCWD, b"/a").unwrap()[..8],
        owner.stat_at(AT_FDCWD, b"/").unwrap()[..8]
    );
    assert_eq!(finish(&worker, unmount(b"/a", 0)), Ok(0));
}
