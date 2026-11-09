// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn finish(paths: &PathQueries, call: NamespaceCall) -> Result<FileValue> {
    match paths.namespace_attempt(call) {
        NamespaceAttempt::Complete(result) => result,
        NamespaceAttempt::Retained(work) => match work.run() {
            FileOutcome::Complete(reply) => reply.result,
            _ => panic!("uncontended original namespace must complete on its caller"),
        },
    }
}
fn mount(paths: &PathQueries, target: &[u8]) {
    assert!(matches!(
        finish(
            paths,
            NamespaceCall::Mount {
                source: None,
                target: target.to_vec(),
                kind: Some(b"mqueue".to_vec()),
                flags: 14,
                data: None,
            }
        ),
        Ok(FileValue::Count(0))
    ));
}
fn setup() -> Vfs {
    let mut owner = Vfs::default();
    for path in [b"/a", b"/b", b"/c"] {
        owner.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
    }
    owner
}
#[test]
fn original_mqueue_mounts_share_live_paths_metadata_and_directory_cursors() {
    let mut owner = setup();
    // Capture before mounting: workers must use the original namespace rather
    // than an owner-refreshed mount projection.
    let query = owner.path_queries();
    mount(&query, b"/a");
    mount(&query, b"/b");
    let a = query.stat_at(AT_FDCWD, b"/a", false).unwrap().unwrap();
    let b = query.stat_at(AT_FDCWD, b"/b", false).unwrap().unwrap();
    assert_eq!(&a[..16], &b[..16]);
    assert_ne!(
        query.mount_id_at(AT_FDCWD, b"/a", false),
        query.mount_id_at(AT_FDCWD, b"/b", false)
    );
    let mut epoch = FileEpoch::default();
    let files = epoch.capture(&owner, true);
    let fd = query
        .open_at_resolve(AT_FDCWD, b"/a", O_DIRECTORY, 0, 0, &files)
        .unwrap()
        .unwrap();
    assert_eq!(query.stat_at(fd as i32, b".", false), Some(Ok(a)));
    assert_eq!(query.stat_fd(fd), Some(Ok(a)));
    assert_eq!(
        query.access_at(AT_FDCWD, b"/b", 3, true, false),
        Some(Ok(()))
    );
    assert!(
        matches!(finish(&query, NamespaceCall::Statfs {fd: fd as i32, path: None}), Ok(FileValue::Bytes(bytes)) if u64::from_le_bytes(bytes[..8].try_into().unwrap()) == 0x19800202)
    );
    assert_eq!(
        query.getdents(fd, 24, || Ok(())).unwrap().unwrap()[19],
        b'.'
    );
    let next = owner.getdents(fd, 24).unwrap();
    assert_eq!(&next[19..21], b"..");
    assert!(query
        .getdents(fd, 4096, || Ok(()))
        .unwrap()
        .unwrap()
        .is_empty());
    assert_eq!(query.directory_seek(fd, 0, 0), Some(Ok(0)));
    assert_eq!(
        query.getdents(fd, 24, || Err(Errno(14))),
        Some(Err(Errno(14)))
    );
    assert_eq!(owner.getdents(fd, 24).unwrap()[19], b'.');
    assert_eq!(
        query.open_at_resolve(AT_FDCWD, b"/a/queue", 0x42, 0o600, 0, &files),
        Some(Err(Errno(1)))
    );
    assert!(matches!(
        finish(
            &query,
            NamespaceCall::Mkdir {
                fd: AT_FDCWD,
                path: b"/b/dir".to_vec(),
                mode: 0o700
            }
        ),
        Err(Errno(1))
    ));
    owner.mount(None, b"/b", None, 32 | 1, None).unwrap();
    assert_eq!(
        query.open_at_resolve(AT_FDCWD, b"/b/queue", 0x42, 0o600, 0, &files),
        Some(Err(Errno(30)))
    );
    // Detached OFDs retain the old mount; a replacement mount affects new paths.
    owner.umount(b"/a", 2).unwrap();
    owner.mount(None, b"/a", Some(b"tmpfs"), 0, None).unwrap();
    assert_eq!(query.stat_fd(fd), Some(Ok(a)));
    assert_eq!(query.stat_at(fd as i32, b".", false), Some(Ok(a)));
    assert_ne!(
        query.stat_at(AT_FDCWD, b"/a", false).unwrap().unwrap()[..16],
        a[..16]
    );
    owner.close(fd).unwrap();
    assert_eq!(query.stat_fd(fd), Some(Err(Errno(9))));
}

#[test]
fn mqueue_source_mounts_use_their_original_ipc_namespace_and_retained_mounts() {
    let mut owner = setup();
    let original = owner.path_queries();
    mount(&original, b"/a");
    let old = original.stat_at(AT_FDCWD, b"/a", false).unwrap().unwrap();
    owner.unshare_ipc().unwrap();
    let private = owner.path_queries();
    mount(&private, b"/b");
    // The previously accepted resolver retains the original IPC namespace.
    std::thread::spawn(move || mount(&original, b"/c"))
        .join()
        .unwrap();
    let b = private.stat_at(AT_FDCWD, b"/b", false).unwrap().unwrap();
    let c = private.stat_at(AT_FDCWD, b"/c", false).unwrap().unwrap();
    assert_ne!(&old[..8], &b[..8]);
    assert_eq!(&old[..16], &c[..16]);
    // Sharing the mount namespace does not change which IPC object each mount pins.
    assert_eq!(private.stat_at(AT_FDCWD, b"/a", false), Some(Ok(old)));
}
