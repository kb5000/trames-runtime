// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn names(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let size = u16::from_le_bytes(bytes[offset + 16..offset + 18].try_into().unwrap()) as usize;
        assert!(size >= 24 && size % 8 == 0 && offset + size <= bytes.len());
        let name = &bytes[offset + 19..offset + size];
        out.push(name[..name.iter().position(|b| *b == 0).unwrap()].to_vec());
        offset += size;
    }
    out
}
#[test]
fn workers_aliases_and_fork_advance_one_original_directory_cursor() {
    let mut owner = Vfs::default();
    owner.mkdir_at(AT_FDCWD, b"/dir", 0o755).unwrap();
    for i in 0..64 {
        owner
            .import_file(format!("/dir/f{i:02}").as_bytes(), vec![])
            .unwrap();
    }
    let fd = owner.open_at(AT_FDCWD, b"/dir", O_DIRECTORY, 0).unwrap();
    let alias = owner.dup(fd, 0, false).unwrap();
    let mut child = owner.clone();
    let jobs: Vec<_> = (0..4)
        .map(|i| {
            let q = child.path_queries();
            std::thread::spawn(move || {
                let mut found = Vec::new();
                loop {
                    let entries = q
                        .getdents(if i % 2 == 0 { fd } else { alias }, 24, || Ok(()))
                        .unwrap()
                        .unwrap();
                    if entries.is_empty() {
                        break;
                    }
                    assert_eq!(entries.len(), 24);
                    found.extend(names(&entries));
                }
                found
            })
        })
        .collect();
    let found: Vec<_> = jobs
        .into_iter()
        .flat_map(|job| job.join().unwrap())
        .collect();
    assert_eq!(found.len(), 66);
    assert_eq!(
        found
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        66
    );
    assert_eq!(owner.seek(fd, 0, 1), Ok(66));
    assert_eq!(child.seek(alias, 0, 0), Ok(0));
    assert_eq!(names(&owner.getdents(fd, 24).unwrap()), vec![b".".to_vec()]);
    assert_eq!(
        child.path_queries().directory_seek(alias, 0, 1),
        Some(Ok(1))
    );
    assert_eq!(
        names(&child.getdents(alias, 24).unwrap()),
        vec![b"..".to_vec()]
    );
    owner.set_runtime_info(
        1,
        RuntimeInfo {
            processes: vec![ProcessInfo {
                pid: 1,
                tgid: 1,
                fds: owner.fd_snapshot(),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let info = owner
        .open_at(AT_FDCWD, format!("/proc/self/fdinfo/{fd}").as_bytes(), 0, 0)
        .unwrap();
    assert!(String::from_utf8(owner.read(info, 4096).unwrap())
        .unwrap()
        .contains("pos:\t2\n"));
}
#[test]
fn preflight_retains_original_ofd_and_faults_leave_its_cursor_untouched() {
    let mut owner = Vfs::default();
    owner.mkdir_at(AT_FDCWD, b"/dir", 0o755).unwrap();
    let fd = owner.open_at(AT_FDCWD, b"/dir", O_DIRECTORY, 0).unwrap();
    let alias = owner.dup(fd, 0, false).unwrap();
    let q = owner.path_queries();
    assert_eq!(q.getdents(fd, 24, || Err(Errno(14))), Some(Err(Errno(14))));
    assert_eq!(q.getdents(fd, 23, || Ok(())), Some(Err(Errno(22))));
    assert_eq!(owner.seek(alias, 0, 1), Ok(0));
    let got = q
        .getdents(fd, 24, || {
            owner.close(fd).unwrap();
            assert_eq!(owner.memfd_create(b"reuse", 0).unwrap(), fd);
            Ok(())
        })
        .unwrap()
        .unwrap();
    assert_eq!(names(&got), vec![b".".to_vec()]);
    assert_eq!(owner.seek(alias, 0, 1), Ok(1));
    assert_eq!(q.getdents(fd, 24, || Ok(())), Some(Err(Errno(20))));
    assert_eq!(
        q.directory_seek(fd, 0, 0),
        None,
        "not a directory byte capability"
    );
    assert_eq!(
        q.getdents(999, 24, || panic!(
            "invalid fd must precede output validation"
        )),
        Some(Err(Errno(9)))
    );
    let path = owner.open_at(AT_FDCWD, b"/dir", O_PATH, 0).unwrap();
    assert_eq!(q.getdents(path, 24, || Ok(())), Some(Err(Errno(9))));
    assert_eq!(q.directory_seek(path, 0, 0), Some(Err(Errno(9))));
    assert_eq!(q.directory_seek(alias, -1, 0), Some(Err(Errno(22))));
    assert_eq!(owner.seek(alias, 0, 1), Ok(1));
}
#[test]
fn volatile_directory_defers_without_output_validation_or_cursor_effects() {
    let mut owner = Vfs::default();
    owner.set_runtime_info(
        1,
        RuntimeInfo {
            processes: vec![ProcessInfo {
                pid: 1,
                tgid: 1,
                fds: owner.fd_snapshot(),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let fd = owner
        .open_at(AT_FDCWD, b"/proc/self/fd", O_DIRECTORY, 0)
        .unwrap();
    let q = owner.path_queries();
    assert_eq!(
        q.getdents(fd, 4096, || panic!("owner-only lookup must defer first")),
        None
    );
    assert_eq!(q.directory_seek(fd, 1, 0), None);
    assert_eq!(names(&owner.getdents(fd, 24).unwrap()), vec![b".".to_vec()]);
}
#[test]
fn worker_directory_open_and_detached_submount_keep_original_membership() {
    let mut owner = Vfs::default();
    for path in [b"/a".as_slice(), b"/a/sub", b"/b"] {
        owner.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
    }
    owner
        .mount(None, b"/a/sub", Some(b"tmpfs"), 0, None)
        .unwrap();
    let live = owner
        .open_at(AT_FDCWD, b"/a/sub/live", 0x42, 0o600)
        .unwrap();
    owner.write(live, &[1]).unwrap();
    owner.close(live).unwrap();
    owner
        .mount(Some(b"/a"), b"/b", None, 4096 | 16384, None)
        .unwrap();
    let mut epoch = FileEpoch::default();
    let files = epoch.capture(&owner, true);
    let q = owner.path_queries();
    let fd = q
        .open_at_resolve(AT_FDCWD, b"/b", O_DIRECTORY | O_CLOEXEC, 0, 0, &files)
        .unwrap()
        .unwrap();
    assert!(owner.fds.get(&fd).unwrap().cloexec.get());
    drop(q); // A path query must not be the pin retaining the original tree.
    owner.umount(b"/b", 2).unwrap();
    let q = owner.path_queries();
    let sub = q
        .open_at_resolve(fd as i32, b"sub", O_DIRECTORY, 0, 0, &files)
        .unwrap()
        .unwrap();
    assert!(names(&q.getdents(sub, 4096, || Ok(())).unwrap().unwrap()).contains(&b"live".to_vec()));
    assert_eq!(q.directory_seek(sub, 0, 0), Some(Ok(0)));
    let expected = owner.getdents(sub, 4096).unwrap();
    q.directory_seek(sub, 0, 0).unwrap().unwrap();
    assert_eq!(q.getdents(sub, 4096, || Ok(())), Some(Ok(expected)));
    owner.close(sub).unwrap();
    owner.close(fd).unwrap();
    drop(q);
    owner.reap_detached_mounts();
    assert!(owner.detached_mounts.borrow().is_empty());
    epoch.finish();
}
#[cfg(all(feature = "hostfs", unix))]
#[test]
fn worker_host_directory_uses_live_children_and_the_same_cookies() {
    let root = std::env::temp_dir().join(format!("trames-dir-worker-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("before"), b"x").unwrap();
    let mut owner = Vfs::default();
    owner.mkdir_at(AT_FDCWD, b"/host", 0o755).unwrap();
    owner.mount_host(b"/host", &root, false).unwrap();
    let fd = owner.open_at(AT_FDCWD, b"/host", O_DIRECTORY, 0).unwrap();
    let q = owner.path_queries();
    let expected = owner.getdents(fd, 4096).unwrap();
    assert_eq!(q.directory_seek(fd, 0, 0), Some(Ok(0)));
    assert_eq!(q.getdents(fd, 4096, || Ok(())), Some(Ok(expected)));
    std::fs::rename(root.join("before"), root.join("after")).unwrap();
    q.directory_seek(fd, 0, 0).unwrap().unwrap();
    let got = names(&q.getdents(fd, 4096, || Ok(())).unwrap().unwrap());
    assert!(got.contains(&b"after".to_vec()) && !got.contains(&b"before".to_vec()));
    owner.close(fd).unwrap();
    drop(q);
    drop(owner);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn directory_walk_and_concurrent_creation_finish_without_nested_namespace_reads() {
    let mut owner = Vfs::default();
    owner.mkdir_at(AT_FDCWD, b"/read", 0o755).unwrap();
    owner.mkdir_at(AT_FDCWD, b"/write", 0o755).unwrap();
    let fd = owner.open_at(AT_FDCWD, b"/read", O_DIRECTORY, 0).unwrap();
    let mut epoch = FileEpoch::default();
    let barrier = Arc::new(std::sync::Barrier::new(6));
    let (sent, received) = std::sync::mpsc::channel();
    let jobs: Vec<_> = (0..6)
        .map(|i| {
            let q = owner.path_queries();
            let files = epoch.capture(&owner, true);
            let membership = owner.shared_files();
            let barrier = barrier.clone();
            let sent = sent.clone();
            std::thread::spawn(move || {
                barrier.wait();
                for n in 0..if i < 4 { 1000 } else { 256 } {
                    if i < 4 {
                        q.directory_seek(fd, 0, 0).unwrap().unwrap();
                        let bytes = q.getdents(fd, 4096, || Ok(())).unwrap().unwrap();
                        assert!(
                            bytes.is_empty()
                                || names(&bytes) == vec![b".".to_vec(), b"..".to_vec()]
                        );
                    } else {
                        let path = format!("/write/{i}-{n}");
                        let file = q
                            .open_at_resolve(AT_FDCWD, path.as_bytes(), 0x42, 0o600, 0, &files)
                            .unwrap()
                            .unwrap();
                        membership.close(file, 0).unwrap().unwrap();
                    }
                }
                sent.send(()).unwrap();
            })
        })
        .collect();
    drop(sent);
    for _ in 0..6 {
        if received
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_err()
        {
            // A failed regression must report failure, not deadlock its own
            // cleanup on the namespace held by the blocked test workers.
            std::mem::forget(owner);
            std::mem::forget(epoch);
            panic!("directory readers/namespace creators failed to make progress");
        }
    }
    for job in jobs {
        job.join().unwrap();
    }
    epoch.finish();
}
