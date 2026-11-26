// SPDX-License-Identifier: GPL-3.0-or-later
//! Projection IO suspension preserves bytes without publishing ID changes.
use super::*;
use crate::user_namespace::{MapFile, MapKind};

struct Store(std::path::PathBuf);
impl Store {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "trames-projection-origin-{}-{}",
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
fn mapped(v: &mut Vfs, source: &[u8], target: &[u8], offset: u32, inverse: bool) {
    let mut child = v.clone();
    child.unshare_user().unwrap();
    let namespace = child.credentials.user_namespace.clone();
    let bytes = if inverse {
        format!("0 {offset} 60000\n")
    } else {
        format!("{offset} 0 60000\n")
    };
    for kind in [MapKind::Uid, MapKind::Gid] {
        MapFile::new(namespace.clone(), v.credentials.clone(), kind)
            .write(bytes.as_bytes(), 0, &v.credentials)
            .unwrap();
    }
    let map = Arc::new(idmap::MountIdmap {
        mapping: Arc::new(namespace.idmapping()),
        namespace,
    });
    let tree = v.open_tree(AT_FDCWD, source, 1).unwrap();
    v.mount_setattr(
        tree as i32,
        b"",
        0x1000,
        &MountAttributes::new(0x100000, 0, 0)
            .unwrap()
            .with_idmap(map),
    )
    .unwrap();
    v.move_mount_fd(tree as i32, b"", AT_FDCWD, target, 4)
        .unwrap();
    v.close(tree).unwrap();
}
fn record() -> Vec<u8> {
    let mut bytes = vec![0; 20];
    bytes[..4].copy_from_slice(&0x02000001u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&(1u32 << capabilities::SETUID).to_le_bytes());
    bytes
}
fn cap_root(node: &NodeRef) -> Option<u32> {
    node.borrow().file_caps().map(|caps| {
        let bytes = caps.encode(&UserNamespace::default()).unwrap();
        if bytes.len() == 20 {
            0
        } else {
            u32::from_le_bytes(bytes[20..24].try_into().unwrap())
        }
    })
}
fn provider(node: &NodeRef) -> Arc<file_data::PlainFile> {
    let n = node.borrow();
    let Content::File(data) = &n.content else {
        panic!("file")
    };
    data.projection_caps(None).unwrap().0
}
fn sidecar(node: &NodeRef) -> std::path::PathBuf {
    let n = node.borrow();
    let Content::File(data) = &n.content else {
        panic!("file")
    };
    data.disk_source().unwrap().0.path.with_extension("cap")
}
fn temporary(store: &Store) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(store.0.join("objects"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap().to_string_lossy().len() == 37)
        .collect()
}
fn stat(v: &mut Vfs, group: &str, key: &str) -> u64 {
    let path = format!("/sys/fs/cgroup/{group}/io.stat");
    let fd = v.open_at(AT_FDCWD, path.as_bytes(), 0, 0).unwrap();
    let bytes = v.pread(fd, 4096, 0).unwrap();
    v.close(fd).unwrap();
    String::from_utf8(bytes)
        .unwrap()
        .split_whitespace()
        .find_map(|part| part.strip_prefix(key).map(|value| value.parse().unwrap()))
        .unwrap_or(0)
}
fn wave(v: &mut Vfs) {
    write(v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=max");
    write(v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=1");
}
fn fixture(
    store: &Store,
    count: usize,
    nested_lower: bool,
) -> (Vfs, Arc<overlay::Overlay>, Vec<NodeRef>) {
    let mut v = Vfs::open_disk(&store.0, Default::default()).unwrap();
    v.set_runtime_info(1, Default::default());
    for path in [
        b"/lower".as_slice(),
        b"/upper-store",
        b"/upper-map",
        b"/merged",
        b"/first",
        b"/first-map",
        b"/first-store",
        b"/first-upper",
    ] {
        v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
    }
    for root in ["/upper-store", "/first-store"] {
        for tail in ["u", "w"] {
            let path = format!("{root}/{tail}");
            v.mkdir_at(AT_FDCWD, path.as_bytes(), 0o755).unwrap();
            v.chown_at(AT_FDCWD, path.as_bytes(), 1000, 1000, true)
                .unwrap();
        }
    }
    for index in 0..count {
        let path = format!("/lower/file{index}");
        v.import_file(path.as_bytes(), b"original data".to_vec())
            .unwrap();
        v.set_xattr(
            AT_FDCWD,
            Some(path.as_bytes()),
            true,
            file_caps::NAME,
            Some(&record()),
            0,
        )
        .unwrap();
    }
    if nested_lower {
        mapped(&mut v, b"/first-store", b"/first-upper", 1000, false);
        v.mount(
            None,
            b"/first",
            Some(b"overlay"),
            0,
            Some(b"lowerdir=/lower,upperdir=/first-upper/u,workdir=/first-upper/w"),
        )
        .unwrap();
        for index in 0..count {
            let path = format!("/first/file{index}");
            let fd = v.open_at(AT_FDCWD, path.as_bytes(), 2, 0).unwrap();
            v.close(fd).unwrap();
        }
        mapped(&mut v, b"/first", b"/first-map", 1000, true);
    }
    mapped(&mut v, b"/upper-store", b"/upper-map", 1000, false);
    let options: &[u8] = if nested_lower {
        b"lowerdir=/first-map,upperdir=/upper-map/u,workdir=/upper-map/w"
    } else {
        b"lowerdir=/lower,upperdir=/upper-map/u,workdir=/upper-map/w"
    };
    v.mount(None, b"/merged", Some(b"overlay"), 0, Some(options))
        .unwrap();
    let fs = v.mount_location(b"/merged", true).unwrap().filesystem(&v);
    let overlay = fs.overlay_handle().unwrap().clone();
    let nodes: Vec<_> = (0..count)
        .map(|index| fs.borrow().paths[format!("/file{index}").as_bytes()].clone())
        .collect();
    // Isolate projection from already completed data/capability copy-up.
    for node in &nodes {
        overlay.copy_up(node, false).unwrap();
    }
    write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"+io");
    for path in [b"/sys/fs/cgroup/a".as_slice(), b"/sys/fs/cgroup/b"] {
        v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
    }
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    (v, overlay, nodes)
}
fn accept(v: &Vfs) -> FileWork {
    let mut epoch = FileEpoch::default();
    let files = epoch.capture(v, true);
    let query = v.path_queries();
    assert!(query
        .open_at_resolve(AT_FDCWD, b"/merged/file0", 2, 0, 0, &files)
        .is_none());
    query.take_open_work().expect("retained original open")
}
fn finish(work: FileWork) -> Result<u32> {
    let mut outcome = work.run();
    for _ in 0..4 {
        outcome = match outcome {
            FileOutcome::Complete(reply) => {
                return match reply.result? {
                    FileValue::Count(fd) => Ok(fd as u32),
                    _ => panic!("open result"),
                }
            }
            FileOutcome::Layout(work) => {
                let admission = work.begin_layout().unwrap().try_enter().ok().unwrap();
                work.enter_layout(admission).run()
            }
            FileOutcome::Waiting(work) if work.ready() => work.run(),
            _ => panic!("unexpected open wait"),
        };
    }
    panic!("bounded completion")
}

#[test]
fn idmapped_projection_retains_one_unpublished_payload_until_manifest_credit_or_cancellation() {
    for nested in [false, true] {
        for cancel in [false, true] {
            let store = Store::new();
            let (mut v, _overlay, nodes) = fixture(&store, 1, nested);
            let root = if nested { 1000 } else { 0 };
            let stored_root = root + 1000;
            let path = sidecar(&nodes[0]);
            let original = std::fs::read(&path).unwrap();
            let manifest = std::fs::read(store.0.join("manifest")).unwrap();
            write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=1");
            let task = v.cgroup_task(1).unwrap();
            let scope = task.resource_scope();
            let work = accept(&v);
            assert!(!work.ready());
            assert_eq!(cap_root(&nodes[0]), Some(root));
            assert_eq!(std::fs::read(&path).unwrap(), original);
            assert_eq!(std::fs::read(store.0.join("manifest")).unwrap(), manifest);
            assert_eq!(temporary(&store).len(), 1);
            assert_eq!(stat(&mut v, "a", "wios="), 1);
            drop(scope);
            assert_eq!(v.stat_at(AT_FDCWD, b"/upper-store/u/file0"), Err(Errno(2)));
            write(&mut v, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
            if cancel {
                drop(work);
                assert_eq!(std::fs::read(&path).unwrap(), original);
                assert_eq!(cap_root(&nodes[0]), Some(root));
                assert_eq!(stat(&mut v, "a", "wios="), 1);
            } else {
                wave(&mut v);
                let resources = task.resource_context();
                let fd = std::thread::spawn(move || {
                    let _other = resources.enter();
                    finish(work).unwrap()
                })
                .join()
                .unwrap();
                assert_eq!(cap_root(&nodes[0]), Some(root));
                let bytes = std::fs::read(&path).unwrap();
                assert_eq!(
                    u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
                    stored_root
                );
                assert_eq!(stat(&mut v, "a", "wios="), 2);
                assert_eq!(
                    stat(&mut v, "a", "wbytes="),
                    24 + std::fs::metadata(store.0.join("manifest")).unwrap().len()
                );
                assert_eq!(v.pread(fd, 32, 0).unwrap(), b"original data");
            }
            assert!(temporary(&store).is_empty());
            assert_eq!(stat(&mut v, "b", "wios="), 0);
        }
    }
}

#[test]
fn two_projected_inodes_keep_completed_sidecars_across_separate_iops_waves() {
    let store = Store::new();
    let (mut v, _overlay, nodes) = fixture(&store, 2, false);
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=1");
    let task = v.cgroup_task(1).unwrap();
    let _scope = task.resource_scope();
    let work = accept(&v);
    assert!(!work.ready());
    assert_eq!(temporary(&store).len(), 1);
    wave(&mut v);
    let FileOutcome::Waiting(work) = work.run() else {
        panic!("manifest waits after second payload")
    };
    assert!(!work.ready());
    assert_eq!(temporary(&store).len(), 2);
    for node in &nodes {
        assert_eq!(cap_root(node), Some(0));
    }
    assert_eq!(stat(&mut v, "a", "wios="), 2);
    wave(&mut v);
    finish(work).unwrap();
    assert_eq!(stat(&mut v, "a", "wios="), 3);
    assert_eq!(
        stat(&mut v, "a", "wbytes="),
        48 + std::fs::metadata(store.0.join("manifest")).unwrap().len()
    );
    assert!(temporary(&store).is_empty());
}

#[test]
fn a_real_manifest_rename_error_restores_projected_sidecars_without_another_budget_wait() {
    let store = Store::new();
    let (mut v, _overlay, nodes) = fixture(&store, 2, false);
    let paths: Vec<_> = nodes.iter().map(sidecar).collect();
    let original: Vec<_> = paths
        .iter()
        .map(|path| std::fs::read(path).unwrap())
        .collect();
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=1");
    let task = v.cgroup_task(1).unwrap();
    let scope = task.resource_scope();
    let work = accept(&v);
    assert!(!work.ready());
    wave(&mut v);
    let FileOutcome::Waiting(work) = work.run() else {
        panic!("manifest waits after both payloads")
    };
    assert!(!work.ready());
    assert_eq!(stat(&mut v, "a", "wios="), 2);
    drop(scope);
    std::fs::rename(store.0.join("manifest"), store.0.join("manifest.saved")).unwrap();
    std::fs::create_dir(store.0.join("manifest")).unwrap();
    wave(&mut v);
    assert_eq!(finish(work), Err(Errno(5)));
    for ((node, path), bytes) in nodes.iter().zip(&paths).zip(original) {
        assert_eq!(cap_root(node), Some(0));
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
    assert_eq!(stat(&mut v, "a", "wios="), 3);
    assert!(temporary(&store).is_empty());
    assert!(!store.0.join("manifest.new").exists());
    std::fs::remove_dir(store.0.join("manifest")).unwrap();
    std::fs::rename(store.0.join("manifest.saved"), store.0.join("manifest")).unwrap();
    assert_eq!(v.stat_at(AT_FDCWD, b"/upper-store/u/file0"), Err(Errno(2)));
}

#[test]
fn revoking_a_capability_during_projection_wait_does_not_restore_the_staged_grant() {
    let store = Store::new();
    let (mut v, _overlay, nodes) = fixture(&store, 1, false);
    let file = provider(&nodes[0]);
    let path = sidecar(&nodes[0]);
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=1");
    let task = v.cgroup_task(1).unwrap();
    let scope = task.resource_scope();
    let work = accept(&v);
    assert!(!work.ready());
    drop(scope);
    file.write_at(0, b"changed").unwrap();
    assert_eq!(cap_root(&nodes[0]), None);
    assert!(!path.exists());
    wave(&mut v);
    let fd = finish(work).unwrap();
    assert_eq!(cap_root(&nodes[0]), None);
    assert!(!path.exists());
    assert_eq!(v.pread(fd, 7, 0).unwrap(), b"changed");
    assert_eq!(stat(&mut v, "a", "wios="), 2);
    assert!(temporary(&store).is_empty());
}

#[test]
fn projection_releases_earlier_provider_transactions_when_a_later_provider_is_busy() {
    let store = Store::new();
    let (mut v, _overlay, nodes) = fixture(&store, 2, false);
    let mut providers: Vec<_> = nodes.iter().map(provider).collect();
    providers.sort_by_key(|file| Arc::as_ptr(file) as usize);
    let busy = providers[1].begin_transaction().unwrap().unwrap();
    let task = v.cgroup_task(1).unwrap();
    let scope = task.resource_scope();
    let work = accept(&v);
    assert!(!work.ready());
    drop(scope);
    let earlier = providers[0].begin_transaction().unwrap().unwrap();
    for node in &nodes {
        assert_eq!(cap_root(node), Some(0));
    }
    assert_eq!(temporary(&store).len(), 2);
    drop(earlier);
    drop(busy);
    assert!(work.ready());
    finish(work).unwrap();
    assert_eq!(stat(&mut v, "a", "wios="), 3);
    assert!(temporary(&store).is_empty());
}

#[test]
fn reopening_a_store_discards_only_owned_abandoned_projection_files() {
    let store = Store::new();
    let cap_path = {
        let mut v = Vfs::open_disk(&store.0, Default::default()).unwrap();
        v.import_file(b"/file", b"original data".to_vec()).unwrap();
        v.set_xattr(
            AT_FDCWD,
            Some(b"/file"),
            true,
            file_caps::NAME,
            Some(&record()),
            0,
        )
        .unwrap();
        let node = v.node(&v.resolve(AT_FDCWD, b"/file").unwrap()).unwrap();
        sidecar(&node)
    };
    let original = std::fs::read(&cap_path).unwrap();
    let stem = cap_path.file_stem().unwrap().to_str().unwrap();
    let garbage: Vec<_> = ["new", "old", "pub"]
        .into_iter()
        .enumerate()
        .map(|(index, extension)| {
            let path = cap_path.with_file_name(format!("{stem}.{:016x}.{extension}", index + 1));
            std::fs::write(&path, b"abandoned payload").unwrap();
            path
        })
        .collect();
    let foreign = cap_path.with_file_name("foreign.old");
    std::fs::write(&foreign, b"unrecognized store entry").unwrap();
    assert!(matches!(
        Vfs::open_disk(&store.0, Default::default()),
        Err(Errno(22))
    ));
    // Recovery validates every entry before deleting any recognized garbage.
    for path in &garbage {
        assert!(path.exists());
    }
    assert_eq!(
        std::fs::read(&foreign).unwrap(),
        b"unrecognized store entry"
    );
    std::fs::remove_file(foreign).unwrap();
    let reopened = Vfs::open_disk(&store.0, Default::default()).unwrap();
    assert_eq!(std::fs::read(cap_path).unwrap(), original);
    assert_eq!(
        reopened
            .get_xattr(AT_FDCWD, Some(b"/file"), true, file_caps::NAME)
            .unwrap(),
        record()
    );
    for path in garbage {
        assert!(!path.exists());
    }
}
