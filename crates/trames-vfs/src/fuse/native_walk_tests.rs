// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

struct HostRoot(std::path::PathBuf);
impl HostRoot {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "trames-fuse-native-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn attach(&self, v: &mut Vfs) {
        v.mkdir_at(AT_FDCWD, b"/host", 0o755).unwrap();
        v.mount_host(b"/host", &self.0, false).unwrap();
    }
}
impl Drop for HostRoot {
    fn drop(&mut self) {
        fn searchable(path: &std::path::Path) {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::symlink_metadata(path).unwrap().is_dir() {
                // Permission-revocation tests can unwind with a mode-0 child.
                // This fixture owns the entire tree; do not follow symlinks.
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
                for child in std::fs::read_dir(path).unwrap() {
                    searchable(&child.unwrap().path());
                }
            }
        }
        searchable(&self.0);
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn native(work: &FileWork) {
    struct Wake;
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let signal = IoSignal::new(0, Arc::downgrade(&wake));
    assert!(work.host_work() && work.ready());
    assert!(!work.waits_for_fuse() && !work.fuse_interrupt_needed());
    assert!(work.fuse_signal_request().is_none());
    let sources = work.wait_sources(&signal).unwrap();
    assert!(sources.subscriptions.is_empty() && sources.native.is_empty());
}

#[test]
fn a_native_mount_operand_reenters_the_executor_after_its_other_operand_waits_for_fuse() {
    let root = HostRoot::new();
    std::fs::create_dir(root.0.join("target")).unwrap();
    let (mut v, dev) = mounted();
    root.attach(&mut v);
    v.mkdir_at(AT_FDCWD, b"/source", 0o755).unwrap();
    v.mkdir_at(AT_FDCWD, b"/source/inside", 0o755).unwrap();
    let expected = v.stat_at(AT_FDCWD, b"/source/inside").unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = paths.namespace_work(NamespaceCall::Mount {
        source: Some(b"/mnt/link".to_vec()),
        target: b"/host/target".to_vec(),
        kind: None,
        flags: 4096,
        data: None,
    });
    native(&work);
    let work = waiting(work);
    assert!(work.waits_for_fuse() && !work.host_work());
    std::fs::rename(root.0.join("target"), root.0.join("moved")).unwrap();
    std::fs::create_dir(root.0.join("target")).unwrap();
    answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
    let work = waiting(work);
    answer(c, &receive(c, 5, 71), b"/source");
    let work = waiting(work);
    receive(c, 2, 71);
    native(&work);
    assert_eq!(v.stat_at(AT_FDCWD, b"/host/moved/inside"), Err(Errno(2)));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    assert_eq!(
        &v.stat_at(AT_FDCWD, b"/host/moved/inside").unwrap()[..16],
        &expected[..16]
    );
    assert_eq!(v.stat_at(AT_FDCWD, b"/host/target/inside"), Err(Errno(2)));
    v.umount(b"/host/moved", 0).unwrap();
}
fn link(c: &Connection, work: FileWork, target: &[u8]) -> FileWork {
    answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
    let work = waiting(work);
    answer(c, &receive(c, 5, 71), target);
    let work = waiting(work);
    native(&work);
    receive(c, 2, 71);
    work
}
fn proc_native(c: &Connection, work: FileWork, target: &[u8], v: &mut Vfs) -> FileWork {
    answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
    let work = waiting(work);
    answer(c, &receive(c, 5, 71), target);
    let work = waiting(work);
    receive(c, 2, 71);
    let FileOutcome::Owner(work) = work.run() else {
        panic!("proc owner checkpoint")
    };
    let FileOutcome::Waiting(work) = work.resume_owner(v) else {
        panic!()
    };
    let work = waiting(work);
    native(&work);
    work
}

#[test]
fn followed_host_open_yields_before_io_and_keeps_its_reserved_fd() {
    let root = HostRoot::new();
    std::fs::write(root.0.join("file"), b"original").unwrap();
    let (mut v, dev) = mounted();
    root.attach(&mut v);
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/link", 0, 0, 0, &files)
        .is_none());
    let work = link(c, paths.take_open_work().unwrap(), b"/host/file");
    let occupied = v
        .open_at(AT_FDCWD, b"/occupied", O_CREAT | 2, 0o600)
        .unwrap();
    v.mkdir_at(AT_FDCWD, b"/elsewhere", 0o755).unwrap();
    v.chdir(b"/elsewhere").unwrap();
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    assert!((fd as u32) < occupied);
    assert_eq!(v.read(fd as u32, 32).unwrap(), b"original");
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn host_symlink_rejoins_fuse_and_interrupts_only_the_new_request() {
    let root = HostRoot::new();
    std::os::unix::fs::symlink("/mnt/end", root.0.join("alias")).unwrap();
    let (mut v, dev) = mounted();
    root.attach(&mut v);
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    assert!(paths.statx_at(AT_FDCWD, b"/mnt/link", false).is_none());
    let work = link(c, paths.take_fuse_stat().unwrap(), b"/host/alias");
    let work = waiting(work);
    assert!(!work.host_work() && work.waits_for_fuse());
    let request = receive(c, 1, 1);
    assert_eq!(&request[40..], b"end\0");
    work.fuse_signal_request().unwrap().interrupt();
    let interrupt = receive(c, 36, 0);
    assert_eq!(&interrupt[40..48], &id(&request).to_le_bytes());
    answer(c, &interrupt, &[]);
    answer(c, &request, &entry(72, 172, 0o100644));
    assert!(matches!(finish(work), Ok(FileValue::FuseStat(..))));
    receive(c, 2, 72);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn namespace_parent_uses_the_native_walk_job_for_the_host_mutation() {
    let root = HostRoot::new();
    let (mut v, dev) = mounted();
    root.attach(&mut v);
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Mkdir {
        fd: AT_FDCWD,
        path: b"/mnt/link/new".to_vec(),
        mode: 0o700,
    }));
    let work = link(c, work, b"/host");
    assert!(
        !root.0.join("new").exists(),
        "yield precedes the host effect"
    );
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    assert!(root.0.join("new").is_dir());
}

#[test]
fn chdir_publishes_the_shared_cwd_only_after_the_native_stage() {
    let root = HostRoot::new();
    std::fs::create_dir(root.0.join("dir")).unwrap();
    let (mut v, dev) = mounted();
    root.attach(&mut v);
    let shared = v.clone_with_resources(false, true);
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Chdir(b"/mnt/link".to_vec())));
    let work = link(c, work, b"/host/dir");
    assert_eq!(shared.cwd().unwrap(), b"/");
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    assert_eq!(v.cwd().unwrap(), b"/host/dir");
    assert_eq!(shared.cwd().unwrap(), b"/host/dir");
}

#[test]
fn proc_host_directory_components_keep_the_original_anchor_for_stat_open_and_chdir() {
    for operation in 0..3 {
        for suffix in [b"/leaf".as_slice(), b"/.", b"/../peer", b"/"] {
            let root = HostRoot::new();
            for path in [
                "parent",
                "parent/dir",
                "parent/dir/leaf",
                "parent/peer",
                "moved",
                "moved/peer",
                "replacement",
            ] {
                std::fs::create_dir(root.0.join(path)).unwrap();
            }
            let (mut v, dev) = mounted();
            root.attach(&mut v);
            let source = v
                .open_at(AT_FDCWD, b"/host/parent/dir", O_PATH | O_DIRECTORY, 0)
                .unwrap();
            let replacement = v
                .open_at(AT_FDCWD, b"/host/replacement", O_PATH | O_DIRECTORY, 0)
                .unwrap();
            let expected = v
                .stat_at(
                    AT_FDCWD,
                    match suffix {
                        b"/leaf" => b"/host/parent/dir/leaf".as_slice(),
                        b"/../peer" => b"/host/moved/peer",
                        _ => b"/host/parent/dir",
                    },
                )
                .unwrap();
            v.set_runtime_info(
                1,
                RuntimeInfo {
                    processes: vec![ProcessInfo {
                        pid: 1,
                        tgid: 1,
                        fds: v.fd_snapshot(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            );
            let c = dev.connection().unwrap();
            let paths = v.path_queries();
            let mut path = b"/mnt/link".to_vec();
            path.extend_from_slice(suffix);
            let work = match operation {
                0 => {
                    assert!(paths.statx_at(AT_FDCWD, &path, false).is_none());
                    paths.take_fuse_stat().unwrap()
                }
                1 => {
                    let files = FileEpoch::default().capture(&v, true);
                    assert!(paths
                        .open_at_resolve(AT_FDCWD, &path, O_PATH | O_DIRECTORY, 0, 0, &files)
                        .is_none());
                    paths.take_open_work().unwrap()
                }
                _ => waiting(paths.namespace_work(NamespaceCall::Chdir(path))),
            };
            let work = proc_native(
                c,
                work,
                format!("/proc/self/fd/{source}").as_bytes(),
                &mut v,
            );
            v.shared_files().close_range(source, source, 0, 1).unwrap();
            assert_eq!(
                v.shared_files()
                    .duplicate(replacement, source, false)
                    .unwrap()
                    .unwrap(),
                source
            );
            std::fs::rename(root.0.join("parent/dir"), root.0.join("moved/dir")).unwrap();
            std::fs::create_dir(root.0.join("parent/dir")).unwrap();
            std::fs::create_dir(root.0.join("parent/dir/leaf")).unwrap();
            let actual = match (operation, finish(work).unwrap()) {
                (0, FileValue::FuseStat(stat, _)) => stat,
                (1, FileValue::Count(fd)) => v.stat_fd(fd as u32).unwrap(),
                (2, FileValue::Count(0)) => v.stat_at(AT_FDCWD, b".").unwrap(),
                _ => panic!("unexpected pathname result"),
            };
            assert_eq!(
                &actual[..16],
                &expected[..16],
                "operation {operation}, suffix {suffix:?}"
            );
            assert_eq!(c.read(8192), Err(Errno(11)));
        }
    }
}

#[test]
fn proc_host_anchor_follows_mount_identity_after_its_parent_moves() {
    let root = HostRoot::new();
    for path in ["dir", "dir/cover"] {
        std::fs::create_dir(root.0.join(path)).unwrap();
    }
    let (mut v, dev) = mounted();
    root.attach(&mut v);
    v.mount(None, b"/host/dir/cover", Some(b"tmpfs"), 0, None)
        .unwrap();
    let leaf = v
        .open_at(AT_FDCWD, b"/host/dir/cover/leaf", O_CREAT | 2, 0o600)
        .unwrap();
    v.write(leaf, b"mounted").unwrap();
    v.close(leaf).unwrap();
    let expected = v.stat_at(AT_FDCWD, b"/host/dir/cover/leaf").unwrap();
    let source = v
        .open_at(AT_FDCWD, b"/host/dir", O_PATH | O_DIRECTORY, 0)
        .unwrap();
    v.set_runtime_info(
        1,
        RuntimeInfo {
            processes: vec![ProcessInfo {
                pid: 1,
                tgid: 1,
                fds: v.fd_snapshot(),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    assert!(paths
        .statx_at(AT_FDCWD, b"/mnt/link/cover/leaf", false)
        .is_none());
    let work = proc_native(
        c,
        paths.take_fuse_stat().unwrap(),
        format!("/proc/self/fd/{source}").as_bytes(),
        &mut v,
    );
    v.shared_files().close_range(source, source, 0, 1).unwrap();
    std::fs::rename(root.0.join("dir"), root.0.join("moved")).unwrap();
    std::fs::create_dir(root.0.join("dir")).unwrap();
    std::fs::create_dir(root.0.join("dir/cover")).unwrap();
    std::fs::write(root.0.join("dir/cover/leaf"), b"replacement").unwrap();
    let FileValue::FuseStat(actual, _) = finish(work).unwrap() else {
        panic!()
    };
    assert_eq!(&actual[..16], &expected[..16]);
    assert_eq!(
        &v.stat_at(AT_FDCWD, b"/host/moved/cover/leaf").unwrap()[..16],
        &expected[..16]
    );
    v.umount(b"/host/moved/cover", 0).unwrap();
}

#[test]
fn removed_host_directory_proc_jump_can_enter_dot_and_climb_to_its_actual_parent() {
    let root = HostRoot::new();
    std::fs::create_dir(root.0.join("dir")).unwrap();
    let (mut v, dev) = mounted();
    root.attach(&mut v);
    let source = v
        .open_at(AT_FDCWD, b"/host/dir", O_PATH | O_DIRECTORY, 0)
        .unwrap();
    let expected = v.stat_fd(source).unwrap();
    v.set_runtime_info(
        1,
        RuntimeInfo {
            processes: vec![ProcessInfo {
                pid: 1,
                tgid: 1,
                fds: v.fd_snapshot(),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Chdir(b"/mnt/link/.".to_vec())));
    let work = proc_native(
        c,
        work,
        format!("/proc/self/fd/{source}").as_bytes(),
        &mut v,
    );
    v.shared_files().close_range(source, source, 0, 1).unwrap();
    std::fs::remove_dir(root.0.join("dir")).unwrap();
    let completed = finish(work);
    assert!(
        matches!(completed, Ok(FileValue::Count(0))),
        "chdir error {:?}",
        completed.err()
    );
    assert_eq!(v.cwd(), Err(Errno(2)));
    assert_eq!(&v.stat_at(AT_FDCWD, b".").unwrap()[..16], &expected[..16]);
    v.chdir(b"..").unwrap();
    assert_eq!(v.cwd().unwrap(), b"/host");
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn namespace_mutations_keep_the_proc_host_parent_after_fd_reuse_and_rename() {
    for operation in 0..5 {
        let root = HostRoot::new();
        std::fs::create_dir(root.0.join("dir")).unwrap();
        std::fs::write(root.0.join("dir/old"), b"original").unwrap();
        let (mut v, dev) = mounted();
        root.attach(&mut v);
        let source = v
            .open_at(AT_FDCWD, b"/host/dir", O_PATH | O_DIRECTORY, 0)
            .unwrap();
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    fds: v.fd_snapshot(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        let call = match operation {
            0 => NamespaceCall::Mkdir {
                fd: AT_FDCWD,
                path: b"/mnt/link/new".to_vec(),
                mode: 0o700,
            },
            1 => NamespaceCall::Mknod {
                fd: AT_FDCWD,
                path: b"/mnt/link/new".to_vec(),
                mode: 0o100600,
                device: 0,
            },
            2 => NamespaceCall::Symlink {
                fd: AT_FDCWD,
                path: b"/mnt/link/new".to_vec(),
                target: b"old".to_vec(),
            },
            3 => NamespaceCall::Unlink {
                fd: AT_FDCWD,
                path: b"/mnt/link/old".to_vec(),
                directory: false,
            },
            _ => NamespaceCall::Rename {
                oldfd: AT_FDCWD,
                old: b"/mnt/link/old".to_vec(),
                newfd: source as i32,
                new: b"new".to_vec(),
                flags: 0,
            },
        };
        let work = waiting(paths.namespace_work(call));
        let work = proc_native(
            c,
            work,
            format!("/proc/self/fd/{source}").as_bytes(),
            &mut v,
        );
        v.shared_files().close_range(source, source, 0, 1).unwrap();
        std::fs::rename(root.0.join("dir"), root.0.join("moved")).unwrap();
        std::fs::create_dir(root.0.join("dir")).unwrap();
        std::fs::write(root.0.join("dir/old"), b"replacement").unwrap();
        assert!(
            matches!(finish(work), Ok(FileValue::Count(0))),
            "operation {operation}"
        );
        assert_eq!(
            std::fs::read(root.0.join("dir/old")).unwrap(),
            b"replacement"
        );
        assert!(!root.0.join("dir/new").exists());
        if operation == 3 {
            assert!(!root.0.join("moved/old").exists());
        } else {
            assert!(std::fs::symlink_metadata(root.0.join("moved/new")).is_ok());
        }
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn proc_host_chdir_retains_the_directory_across_native_wait_and_path_replacement() {
    proc_host_directory_change(false);
}

#[test]
fn proc_host_chroot_retains_the_directory_across_native_wait_and_path_replacement() {
    proc_host_directory_change(true);
}

fn proc_host_directory_change(root_change: bool) {
    let root = HostRoot::new();
    std::fs::create_dir(root.0.join("dir")).unwrap();
    std::fs::create_dir(root.0.join("replacement")).unwrap();
    let (mut v, dev) = mounted();
    root.attach(&mut v);
    let source = v
        .open_at(AT_FDCWD, b"/host/dir", O_PATH | O_DIRECTORY, 0)
        .unwrap();
    let replacement = v
        .open_at(AT_FDCWD, b"/host/replacement", O_PATH | O_DIRECTORY, 0)
        .unwrap();
    let original = v.stat_fd(source).unwrap();
    v.set_runtime_info(
        1,
        RuntimeInfo {
            processes: vec![ProcessInfo {
                pid: 1,
                tgid: 1,
                fds: v.fd_snapshot(),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let call = if root_change {
        NamespaceCall::Chroot(b"/mnt/link".to_vec())
    } else {
        NamespaceCall::Chdir(b"/mnt/link".to_vec())
    };
    let work = waiting(paths.namespace_work(call));
    answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
    let work = waiting(work);
    answer(
        c,
        &receive(c, 5, 71),
        format!("/proc/self/fd/{source}").as_bytes(),
    );
    let work = waiting(work);
    receive(c, 2, 71);
    let FileOutcome::Owner(work) = work.run() else {
        panic!("proc owner checkpoint")
    };
    let FileOutcome::Waiting(work) = work.resume_owner(&mut v) else {
        panic!()
    };
    let work = waiting(work);
    native(&work);
    assert_eq!(v.cwd().unwrap(), b"/");
    v.shared_files().close_range(source, source, 0, 1).unwrap();
    assert_eq!(
        v.shared_files()
            .duplicate(replacement, source, false)
            .unwrap()
            .unwrap(),
        source
    );
    std::fs::rename(root.0.join("dir"), root.0.join("moved")).unwrap();
    std::fs::create_dir(root.0.join("dir")).unwrap();
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    let actual = if root_change {
        assert!(v.proc_directories().1.unwrap().host_file.is_some());
        let stat = v.stat_at(AT_FDCWD, b"/").unwrap();
        v.chdir(b"/").unwrap();
        assert_eq!(v.cwd().unwrap(), b"/");
        stat
    } else {
        assert_eq!(v.cwd().unwrap(), b"/host/moved");
        v.stat_at(AT_FDCWD, b".").unwrap()
    };
    assert_eq!(&actual[..16], &original[..16]);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn proc_host_cwd_keeps_its_capability_after_the_target_changes_cwd() {
    let root = HostRoot::new();
    std::fs::create_dir(root.0.join("dir")).unwrap();
    let (mut v, dev) = mounted();
    root.attach(&mut v);
    v.chdir(b"/host/dir").unwrap();
    let cwd = v.proc_directories().0;
    let expected = v.stat_at(AT_FDCWD, b".").unwrap();
    v.chdir(b"/").unwrap();
    v.set_runtime_info(
        1,
        RuntimeInfo {
            processes: vec![ProcessInfo {
                pid: 1,
                tgid: 1,
                cwd_directory: cwd,
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Chdir(b"/mnt/link".to_vec())));
    let work = proc_native(c, work, b"/proc/self/cwd", &mut v);
    v.set_runtime_info(
        1,
        RuntimeInfo {
            processes: vec![ProcessInfo {
                pid: 1,
                tgid: 1,
                cwd_directory: v.proc_directories().0,
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    std::fs::rename(root.0.join("dir"), root.0.join("moved")).unwrap();
    std::fs::create_dir(root.0.join("dir")).unwrap();
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    assert_eq!(v.cwd().unwrap(), b"/host/moved");
    assert_eq!(&v.stat_at(AT_FDCWD, b".").unwrap()[..16], &expected[..16]);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn retained_host_chdir_and_fchdir_refresh_search_permission_before_publication() {
    use std::os::unix::fs::PermissionsExt;
    for fd_call in [false, true] {
        for allow in [false, true] {
            let root = HostRoot::new();
            std::fs::create_dir(root.0.join("dir")).unwrap();
            let (mut v, dev) = mounted();
            root.attach(&mut v);
            let source = v.open_at(AT_FDCWD, b"/host/dir", O_DIRECTORY, 0).unwrap();
            // Open while the host owner can acquire a directory fd, then
            // change permissions through the real guest syscall. macOS has
            // no Linux O_PATH bypass for initially mode-0 host directories.
            v.chmod_fd(source, if allow { 0 } else { 0o755 }).unwrap();
            v.set_runtime_info(
                1,
                RuntimeInfo {
                    processes: vec![ProcessInfo {
                        pid: 1,
                        tgid: 1,
                        fds: v.fd_snapshot(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            );
            v.credentials.caps.effective = 0;
            let c = dev.connection().unwrap();
            let paths = v.path_queries();
            let work = if fd_call {
                let work = paths.namespace_work(NamespaceCall::Fchdir(source));
                native(&work);
                work
            } else {
                let work =
                    waiting(paths.namespace_work(NamespaceCall::Chdir(b"/mnt/link".to_vec())));
                proc_native(
                    c,
                    work,
                    format!("/proc/self/fd/{source}").as_bytes(),
                    &mut v,
                )
            };
            v.shared_files().close_range(source, source, 0, 1).unwrap();
            std::fs::set_permissions(
                root.0.join("dir"),
                std::fs::Permissions::from_mode(if allow { 0o755 } else { 0 }),
            )
            .unwrap();
            let result = finish(work);
            if allow {
                assert!(matches!(result, Ok(FileValue::Count(0))));
                assert_eq!(v.cwd().unwrap(), b"/host/dir");
            } else {
                assert!(matches!(result, Err(Errno(13))));
                assert_eq!(v.cwd().unwrap(), b"/");
            }
            assert_eq!(c.read(8192), Err(Errno(11)));
            std::fs::set_permissions(root.0.join("dir"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
    }
}

#[test]
fn proc_host_access_keeps_the_resolved_inode_and_refreshes_its_current_mode() {
    use std::os::unix::fs::PermissionsExt;
    for readable in [false, true] {
        let root = HostRoot::new();
        std::fs::write(root.0.join("file"), b"original").unwrap();
        std::fs::set_permissions(root.0.join("file"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let (mut v, dev) = mounted();
        root.attach(&mut v);
        let source = v.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap();
        let replacement = v.memfd_create(b"replacement", 0).unwrap();
        v.chmod_fd(replacement, if readable { 0 } else { 0o666 })
            .unwrap();
        let publish = |v: &mut Vfs| {
            v.set_runtime_info(
                1,
                RuntimeInfo {
                    processes: vec![ProcessInfo {
                        pid: 1,
                        tgid: 1,
                        fds: v.fd_snapshot(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            )
        };
        publish(&mut v);
        v.credentials.caps.effective = 0;
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        assert!(paths
            .access_at(AT_FDCWD, b"/mnt/link", 4, true, false)
            .is_none());
        let work = paths.take_fuse_stat().unwrap();
        answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
        let work = waiting(work);
        answer(
            c,
            &receive(c, 5, 71),
            format!("/proc/self/fd/{source}").as_bytes(),
        );
        let work = waiting(work);
        receive(c, 2, 71);
        let FileOutcome::Owner(work) = work.run() else {
            panic!()
        };
        let FileOutcome::Waiting(work) = work.resume_owner(&mut v) else {
            panic!()
        };
        let work = waiting(work);
        native(&work);
        v.shared_files().close_range(source, source, 0, 1).unwrap();
        assert_eq!(
            v.shared_files()
                .duplicate(replacement, source, false)
                .unwrap()
                .unwrap(),
            source
        );
        publish(&mut v);
        std::fs::rename(root.0.join("file"), root.0.join("moved")).unwrap();
        std::fs::write(root.0.join("file"), b"replacement path").unwrap();
        std::fs::set_permissions(
            root.0.join("file"),
            std::fs::Permissions::from_mode(if readable { 0 } else { 0o644 }),
        )
        .unwrap();
        std::fs::set_permissions(
            root.0.join("moved"),
            std::fs::Permissions::from_mode(if readable { 0o644 } else { 0 }),
        )
        .unwrap();
        let result = finish(work);
        if readable {
            assert!(matches!(result, Ok(FileValue::Count(0))));
        } else {
            assert!(matches!(result, Err(Errno(13))));
        }
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn cancelled_native_walk_releases_the_original_open_reservation() {
    let root = HostRoot::new();
    let (mut v, dev) = mounted();
    root.attach(&mut v);
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/link", O_CREAT | 2, 0o600, 0, &files)
        .is_none());
    let work = link(c, paths.take_open_work().unwrap(), b"/host/new");
    let occupied = v
        .open_at(AT_FDCWD, b"/occupied", O_CREAT | 2, 0o600)
        .unwrap();
    drop(work);
    let released = v
        .open_at(AT_FDCWD, b"/released", O_CREAT | 2, 0o600)
        .unwrap();
    assert!(released < occupied);
    assert!(!root.0.join("new").exists());
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn open_tree_returns_a_fuse_link_native_target_to_the_existing_executor() {
    let root = HostRoot::new();
    std::fs::create_dir(root.0.join("source")).unwrap();
    let (mut v, dev) = mounted();
    root.attach(&mut v);
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let before = v.fds.entries().len();
    let work = waiting(
        paths.namespace_work(NamespaceCall::MountFd(MountFdCall::Tree {
            fd: AT_FDCWD,
            path: b"/mnt/link".to_vec(),
            flags: 1,
        })),
    );
    answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
    let work = waiting(work);
    answer(c, &receive(c, 5, 71), b"/host/source");
    let work = waiting(work);
    receive(c, 2, 71);
    native(&work);
    assert_eq!(v.fds.entries().len(), before);
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    let expected = v.stat_at(AT_FDCWD, b"/host/source").unwrap();
    let actual = v.stat_fd(fd as u32).unwrap();
    assert_eq!(&actual[..16], &expected[..16]);
    v.close(fd as u32).unwrap();
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn opening_a_bound_daemon_link_carries_the_reservation_to_a_native_target() {
    let root = HostRoot::new();
    std::fs::write(root.0.join("target"), b"native-bytes").unwrap();
    let (mut v, dev) = mounted();
    root.attach(&mut v);
    v.import_file(b"/alias", Vec::new()).unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let tree = waiting(
        paths.namespace_work(NamespaceCall::MountFd(MountFdCall::Tree {
            fd: AT_FDCWD,
            path: b"/mnt/link".to_vec(),
            flags: 1 | 0x100,
        })),
    );
    answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
    let FileValue::Count(fd) = finish(tree).unwrap() else {
        panic!()
    };
    assert!(matches!(
        finish(
            paths.namespace_work(NamespaceCall::MountFd(MountFdCall::Move {
                from: fd as i32,
                source: Vec::new(),
                to: AT_FDCWD,
                target: b"/alias".to_vec(),
                flags: 4,
            }))
        ),
        Ok(FileValue::Count(0))
    ));
    v.close(fd as u32).unwrap();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/alias", 0, 0, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    let before = v.fds.entries().len();
    answer(c, &receive(c, 5, 71), b"/host/target");
    let work = waiting(work);
    native(&work);
    assert_eq!(v.fds.entries().len(), before);
    let FileValue::Count(opened) = finish(work).unwrap() else {
        panic!()
    };
    assert_eq!(v.read(opened as u32, 20).unwrap(), b"native-bytes");
    v.close(opened as u32).unwrap();
    v.umount(b"/alias", 8).unwrap();
    receive(c, 2, 71);
}

#[test]
fn hardlink_keeps_a_native_source_inode_while_its_destination_waits_for_a_fuse_link() {
    let root = HostRoot::new();
    std::fs::write(root.0.join("source"), b"original").unwrap();
    let (mut v, dev) = mounted();
    root.attach(&mut v);
    let expected = v.stat_at(AT_FDCWD, b"/host/source").unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = paths.namespace_work(NamespaceCall::Link {
        oldfd: AT_FDCWD,
        old: b"/host/source".to_vec(),
        newfd: AT_FDCWD,
        new: b"/mnt/parent/alias".to_vec(),
        follow: false,
        empty_path: false,
    });
    native(&work);
    let work = waiting(work);
    answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
    let work = waiting(work);
    let readlink = receive(c, 5, 71);
    std::fs::rename(root.0.join("source"), root.0.join("moved")).unwrap();
    std::fs::write(root.0.join("source"), b"replacement").unwrap();
    answer(c, &readlink, b"/host");
    let work = waiting(work);
    receive(c, 2, 71);
    native(&work);
    let result = finish(work);
    assert!(
        matches!(result, Ok(FileValue::Count(0))),
        "{:?}",
        result.err()
    );
    let alias = v.stat_at(AT_FDCWD, b"/host/alias").unwrap();
    assert_eq!(&alias[..16], &expected[..16]);
    let replacement = v.stat_at(AT_FDCWD, b"/host/source").unwrap();
    assert_ne!(&replacement[..16], &expected[..16]);
}

#[test]
fn xattrs_cross_fuse_and_proc_on_the_native_executor_with_the_original_host_ofd() {
    for operation in 0..5 {
        let root = HostRoot::new();
        std::fs::write(root.0.join("file"), b"original").unwrap();
        std::fs::write(root.0.join("other"), b"replacement").unwrap();
        let (mut v, dev) = mounted();
        root.attach(&mut v);
        v.set_xattr(
            AT_FDCWD,
            Some(b"/host/file"),
            true,
            b"user.original",
            Some(b"original"),
            0,
        )
        .unwrap();
        let source = v.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap();
        let replacement = v.open_at(AT_FDCWD, b"/host/other", 0, 0).unwrap();
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    fds: v.fd_snapshot(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let c = dev.connection().unwrap();
        let call = if operation == 0 || operation == 4 {
            NamespaceCall::Xattr {
                fd: AT_FDCWD,
                path: Some(b"/mnt/link".to_vec()),
                follow: true,
                name: b"user.original".to_vec(),
                value: (operation == 0).then(|| b"changed".to_vec()),
                flags: 0,
            }
        } else {
            NamespaceCall::GetXattr {
                fd: AT_FDCWD,
                path: Some(b"/mnt/link".to_vec()),
                follow: true,
                name: (operation != 3).then(|| b"user.original".to_vec()),
                capacity: if operation == 1 { 0 } else { 65536 },
            }
        };
        let work = waiting(v.path_queries().namespace_work(call));
        let work = proc_native(
            c,
            work,
            format!("/proc/self/fd/{source}").as_bytes(),
            &mut v,
        );
        v.shared_files().close_range(source, source, 0, 1).unwrap();
        assert_eq!(
            v.shared_files()
                .duplicate(replacement, source, false)
                .unwrap()
                .unwrap(),
            source
        );
        std::fs::rename(root.0.join("file"), root.0.join("old")).unwrap();
        std::fs::write(root.0.join("file"), b"new file").unwrap();
        let result = finish(work).unwrap();
        match operation {
            0 | 4 => assert!(matches!(result, FileValue::Count(0))),
            1 => assert!(matches!(result, FileValue::Count(8))),
            2 => assert!(matches!(result, FileValue::Bytes(b) if b == b"original")),
            3 => assert!(
                matches!(result, FileValue::Bytes(b) if b.split(|&c| c == 0).any(|n| n == b"user.original"))
            ),
            _ => unreachable!(),
        }
        let old = v.get_xattr(AT_FDCWD, Some(b"/host/old"), true, b"user.original");
        assert_eq!(
            old,
            if operation == 0 {
                Ok(b"changed".to_vec())
            } else if operation == 4 {
                Err(Errno(61))
            } else {
                Ok(b"original".to_vec())
            }
        );
        for path in [b"/host/file".as_slice(), b"/host/other"] {
            assert_eq!(
                v.get_xattr(AT_FDCWD, Some(path), true, b"user.original"),
                Err(Errno(61))
            );
        }
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}
