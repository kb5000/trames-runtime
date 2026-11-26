// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::user_namespace::{MapFile, MapKind};

fn mapping(v: &Vfs, uid: &[u8], gid: &[u8]) -> Arc<idmap::MountIdmap> {
    let mut child = v.clone();
    child.unshare_user().unwrap();
    let namespace = child.credentials.user_namespace.clone();
    for (kind, bytes) in [(MapKind::Uid, uid), (MapKind::Gid, gid)] {
        MapFile::new(namespace.clone(), v.credentials.clone(), kind)
            .write(bytes, 0, &v.credentials)
            .unwrap();
    }
    Arc::new(idmap::MountIdmap {
        mapping: Arc::new(namespace.idmapping()),
        namespace,
    })
}
fn mapped(v: &mut Vfs, source: &[u8], target: &[u8], map: Arc<idmap::MountIdmap>) -> u32 {
    let tree = v.open_tree(AT_FDCWD, source, 1).unwrap();
    v.mount_setattr(
        tree as i32,
        b"",
        EMPTY,
        &MountAttributes::new(0x100000, 0, 0)
            .unwrap()
            .with_idmap(map),
    )
    .unwrap();
    v.move_mount_fd(tree as i32, b"", AT_FDCWD, target, 4)
        .unwrap();
    tree
}
fn ids(v: &mut Vfs, path: &[u8]) -> (u32, u32) {
    let bytes = v.stat_at(AT_FDCWD, path).unwrap();
    (
        u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
        u32::from_le_bytes(bytes[28..32].try_into().unwrap()),
    )
}
fn setup() -> Vfs {
    let mut v = Vfs::default();
    for p in [b"/source".as_slice(), b"/mapped", b"/alias"] {
        v.mkdir_at(AT_FDCWD, p, 0o755).unwrap();
    }
    v.mount(None, b"/source", Some(b"tmpfs"), 0, Some(b"mode=0777"))
        .unwrap();
    v
}
#[test]
fn idmapped_paths_and_original_ofds_keep_distinct_ownership_after_detach() {
    let mut v = setup();
    let original = v.open_at(AT_FDCWD, b"/source/file", 0x42, 0o600).unwrap();
    let map = mapping(&v, b"0 1000 100\n", b"0 2000 100\n");
    let tree = mapped(&mut v, b"/source", b"/mapped", map);
    assert_eq!(ids(&mut v, b"/source/file"), (0, 0));
    assert_eq!(ids(&mut v, b"/mapped/file"), (1000, 2000));
    v.mount(Some(b"/mapped"), b"/alias", None, 4096, None)
        .unwrap();
    let fd = v.open_at(AT_FDCWD, b"/mapped/file", 0, 0).unwrap();
    let direct = file_io::FileEpoch::default()
        .capture(&v, true)
        .get(fd)
        .unwrap();
    v.close(tree).unwrap();
    v.umount(b"/mapped", 2).unwrap();
    v.chown_fd_at(fd, 1001, 2002).unwrap();
    assert_eq!(ids(&mut v, b"/source/file"), (1, 2));
    assert_eq!(ids(&mut v, b"/alias/file"), (1001, 2002));
    let stat = v.stat_fd(original).unwrap();
    assert_eq!(u32::from_le_bytes(stat[24..28].try_into().unwrap()), 1);
    let stat = v.stat_fd(fd).unwrap();
    assert_eq!(u32::from_le_bytes(stat[24..28].try_into().unwrap()), 1001);
    assert_eq!(direct.stat().unwrap(), stat);
}
#[test]
fn idmapped_creation_dac_chmod_chown_and_unmapped_ids_use_the_actual_mount() {
    let mut v = setup();
    let map = mapping(&v, b"0 1000 100\n", b"0 2000 100\n");
    mapped(&mut v, b"/source", b"/mapped", map);
    let root = v.credentials.clone();
    v.credentials.fsuid = 1003;
    v.credentials.fsgid = 2004;
    v.credentials.caps = capabilities::Capabilities::for_uid(1003);
    let fd = v.open_at(AT_FDCWD, b"/mapped/new", 0x42, 0o600).unwrap();
    assert_eq!(ids(&mut v, b"/source/new"), (3, 4));
    assert_eq!(v.open_at(AT_FDCWD, b"/source/new", 0, 0), Err(Errno(13)));
    v.chmod_at(AT_FDCWD, b"/mapped/new", 0o640).unwrap();
    assert_eq!(v.chmod_at(AT_FDCWD, b"/source/new", 0o600), Err(Errno(1)));
    assert_eq!(v.chown_fd_at(fd, 1005, u32::MAX), Err(Errno(1)));
    v.credentials = root;
    assert_eq!(v.chown_fd_at(fd, 999, u32::MAX), Err(Errno(75)));
    v.chown_at(AT_FDCWD, b"/source/new", 500, 500, true)
        .unwrap();
    let stat = v.credentials.user_namespace.stat(v.stat_fd(fd).unwrap());
    assert_eq!(u32::from_le_bytes(stat[24..28].try_into().unwrap()), 65534);
    assert_eq!(v.open_at(AT_FDCWD, b"/mapped/new", 0, 0), Err(Errno(13)));
    assert_eq!(
        v.open_at(AT_FDCWD, b"/mapped/overflow", 0x42, 0o600),
        Err(Errno(75))
    );
}
#[test]
fn idmap_validation_rolls_back_recursive_attributes_and_is_one_time_only() {
    let mut v = setup();
    let map = mapping(&v, b"0 1000 100\n", b"0 2000 100\n");
    let attrs = || {
        MountAttributes::new(0x100001, 0, 0)
            .unwrap()
            .with_idmap(map.clone())
    };
    assert_eq!(
        v.mount_setattr(AT_FDCWD, b"/source", 0, &attrs()),
        Err(Errno(22))
    );
    v.mkdir_at(AT_FDCWD, b"/source/child", 0o755).unwrap();
    v.mount(None, b"/source/child", Some(b"ramfs"), 0, None)
        .unwrap();
    let tree = v.open_tree(AT_FDCWD, b"/source", 1 | RECURSIVE).unwrap();
    assert_eq!(
        v.mount_setattr(tree as i32, b"", EMPTY | RECURSIVE, &attrs()),
        Err(Errno(22))
    );
    let root = v
        .mount_operand(tree as i32, b"", true, true)
        .unwrap()
        .mount
        .unwrap();
    assert!(root.idmap.get().is_none());
    assert_eq!(root.flags.get() & MS_RDONLY, 0);
    v.mount_setattr(tree as i32, b"", EMPTY, &attrs()).unwrap();
    assert_eq!(
        v.mount_setattr(tree as i32, b"", EMPTY, &attrs()),
        Err(Errno(1))
    );
}
#[test]
fn reconfigure_proc_sysfs_and_ramfs_does_not_change_root_or_local_alias_flags() {
    let mut v = setup();
    v.set_runtime_info(1, Default::default());
    for path in [b"/proc".as_slice(), b"/sys", b"/source"] {
        let ctx = v.fspick(AT_FDCWD, path, 0).unwrap();
        v.fsconfigure(ctx, 0, Some(b"ro"), None).unwrap();
        v.fsconfigure(ctx, 7, None, None).unwrap();
        assert_eq!(v.mkdir_at(AT_FDCWD, b"/root-still-writable", 0o755), Ok(()));
        v.unlink_at(AT_FDCWD, b"/root-still-writable", true)
            .unwrap();
        v.fsconfigure(ctx, 0, Some(b"rw"), None).unwrap();
        v.fsconfigure(ctx, 7, None, None).unwrap();
        v.close(ctx).unwrap();
    }
    v.mount(None, b"/alias", Some(b"ramfs"), 0, None).unwrap();
    let pick = v.fspick(AT_FDCWD, b"/alias", 0).unwrap();
    v.fsconfigure(pick, 0, Some(b"ro"), None).unwrap();
    v.fsconfigure(pick, 7, None, None).unwrap();
    assert_eq!(v.mkdir_at(AT_FDCWD, b"/alias/no", 0o755), Err(Errno(30)));
}
#[test]
fn accepted_empty_idmap_is_immutable_after_namespace_maps_are_written() {
    let mut v = setup();
    let mut child = v.clone();
    child.unshare_user().unwrap();
    let namespace = child.credentials.user_namespace.clone();
    let map = Arc::new(idmap::MountIdmap {
        mapping: Arc::new(namespace.idmapping()),
        namespace: namespace.clone(),
    });
    mapped(&mut v, b"/source", b"/mapped", map);
    for kind in [MapKind::Uid, MapKind::Gid] {
        MapFile::new(namespace.clone(), v.credentials.clone(), kind)
            .write(b"0 1000 100\n", 0, &v.credentials)
            .unwrap();
    }
    let stat = v
        .credentials
        .user_namespace
        .stat(v.stat_at(AT_FDCWD, b"/mapped").unwrap());
    assert_eq!(u32::from_le_bytes(stat[24..28].try_into().unwrap()), 65534);
    assert_eq!(v.mkdir_at(AT_FDCWD, b"/mapped/no", 0o755), Err(Errno(75)));
}
#[test]
fn idmapped_file_caps_use_projected_root_and_setter_ownership() {
    let mut v = setup();
    let fd = v.open_at(AT_FDCWD, b"/source/exe", 0x42, 0o755).unwrap();
    v.close(fd).unwrap();
    let map = mapping(&v, b"0 1000 100\n", b"0 2000 100\n");
    mapped(&mut v, b"/source", b"/mapped", map);
    let mut caps = [0u8; 24];
    caps[..4].copy_from_slice(&0x03000001u32.to_le_bytes());
    caps[4..8].copy_from_slice(&(1u32 << capabilities::NET_BIND_SERVICE).to_le_bytes());
    caps[20..].copy_from_slice(&1000u32.to_le_bytes());
    v.set_xattr(
        AT_FDCWD,
        Some(b"/mapped/exe"),
        true,
        file_caps::NAME,
        Some(&caps),
        0,
    )
    .unwrap();
    let node = v
        .node(&v.resolve(AT_FDCWD, b"/source/exe").unwrap())
        .unwrap();
    assert!(node
        .borrow()
        .file_caps()
        .unwrap()
        .applies(&v.credentials.user_namespace));
    caps[20..].copy_from_slice(&5000u32.to_le_bytes());
    assert_eq!(
        v.set_xattr(
            AT_FDCWD,
            Some(b"/mapped/exe"),
            true,
            file_caps::NAME,
            Some(&caps),
            0
        ),
        Err(Errno(22))
    );
}
#[test]
fn tmpfs_reconfigure_ignores_creation_ownership_and_rolls_back_ro_on_bad_limits() {
    let mut v = setup();
    let ctx = v.fspick(AT_FDCWD, b"/source", 0).unwrap();
    let before = ids(&mut v, b"/source");
    v.fsconfigure(ctx, 1, Some(b"mode"), Some(b"0700")).unwrap();
    v.fsconfigure(ctx, 1, Some(b"uid"), Some(b"1234")).unwrap();
    v.fsconfigure(ctx, 7, None, None).unwrap();
    assert_eq!(ids(&mut v, b"/source"), before);
    v.mkdir_at(AT_FDCWD, b"/source/one", 0o755).unwrap();
    v.fsconfigure(ctx, 1, Some(b"nr_inodes"), Some(b"1"))
        .unwrap();
    v.fsconfigure(ctx, 0, Some(b"ro"), None).unwrap();
    assert_eq!(v.fsconfigure(ctx, 7, None, None), Err(Errno(22)));
    v.mkdir_at(AT_FDCWD, b"/source/still-writable", 0o755)
        .unwrap();
}
#[test]
fn unmapped_inode_writeback_guards_and_chown_recovery_match_the_original_view() {
    let mut v = setup();
    let raw = v.open_at(AT_FDCWD, b"/source/file", 0x42, 0o666).unwrap();
    let map = mapping(&v, b"0 1000 100\n", b"0 2000 100\n");
    mapped(&mut v, b"/source", b"/mapped", map);
    let retained = v.open_at(AT_FDCWD, b"/mapped/file", 2, 0).unwrap();
    v.chown_fd_at(raw, 500, 500).unwrap();
    v.chmod_at(AT_FDCWD, b"/source/file", 0o666).unwrap();
    assert!(v.open_at(AT_FDCWD, b"/mapped/file", 0, 0).is_ok());
    assert_eq!(v.open_at(AT_FDCWD, b"/mapped/file", 1, 0), Err(Errno(13)));
    assert_eq!(v.chmod_at(AT_FDCWD, b"/mapped/file", 0o600), Err(Errno(75)));
    assert_eq!(
        v.unlink_at(AT_FDCWD, b"/mapped/file", false),
        Err(Errno(75))
    );
    assert_eq!(
        v.rename_at(AT_FDCWD, b"/mapped/file", AT_FDCWD, b"/mapped/renamed", 0),
        Err(Errno(75))
    );
    assert_eq!(
        v.link_at(AT_FDCWD, b"/mapped/file", AT_FDCWD, b"/mapped/linked"),
        Err(Errno(75))
    );
    assert_eq!(v.write(retained, b"accepted"), Ok(8));
    assert_eq!(v.truncate_fd(retained, 0), Err(Errno(75)));
    assert_eq!(v.chown_fd_at(retained, 1000, u32::MAX), Err(Errno(75)));
    v.chown_fd_at(retained, 1000, 2000).unwrap();
    assert_eq!(ids(&mut v, b"/source/file"), (0, 0));
    v.chown_fd_at(raw, 0, 500).unwrap();
    assert_eq!(v.chown_fd_at(retained, 1000, 2000), Err(Errno(1)));
    v.chown_fd_at(retained, u32::MAX, 2000).unwrap();
    v.credentials = Credentials::user(1003, 2003);
    v.chown_fd_at(retained, u32::MAX, u32::MAX).unwrap();
}
