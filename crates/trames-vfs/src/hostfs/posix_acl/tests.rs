// SPDX-License-Identifier: GPL-3.0-or-later
use super::super::tests::Fixture;
use super::*;
use std::os::unix::fs::PermissionsExt;
const USER: u32 = 1_000_001;
const GROUP: u32 = 1_000_002;
fn value(user: u32, group: u32) -> Vec<u8> {
    let mut value = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in [
        (1u16, 7u16, u32::MAX),
        (2, 7, user),
        (4, 0, u32::MAX),
        (8, 4, group),
        (16, 7, u32::MAX),
        (32, 0, u32::MAX),
    ] {
        value.extend(tag.to_le_bytes());
        value.extend(perm.to_le_bytes());
        value.extend(id.to_le_bytes());
    }
    value
}
fn set(v: &mut Vfs, path: &[u8], name: &[u8], bytes: Option<&[u8]>, flags: u32) -> Result<()> {
    v.set_xattr(AT_FDCWD, Some(path), true, name, bytes, flags)
}
fn mode(v: &Vfs, path: &[u8]) -> u32 {
    u32::from_le_bytes(
        v.stat_at(AT_FDCWD, path).unwrap()[16..20]
            .try_into()
            .unwrap(),
    ) & 0o7777
}
#[test]
fn native_acl_persists_and_is_checked_before_any_guest_attribute_query() {
    let root = Fixture::new();
    std::fs::write(root.0.join("file"), b"data").unwrap();
    let mut v = root.vfs(false);
    let bytes = value(USER, GROUP);
    set(&mut v, b"/host/file", acl::ACCESS, Some(&bytes), 0).unwrap();
    drop(v);
    let mut user = root.vfs(false);
    user.credentials = Credentials::user(USER, USER);
    let fd = user.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap();
    assert_eq!(user.read(fd, 16).unwrap(), b"data");
    user.credentials = Credentials::user(USER + 2, USER + 2);
    assert_eq!(user.open_at(AT_FDCWD, b"/host/file", 0, 0), Err(Errno(13)));
    user.credentials = Credentials::user(USER + 1, GROUP);
    assert!(user.open_at(AT_FDCWD, b"/host/file", 0, 0).is_ok());
    assert_eq!(user.open_at(AT_FDCWD, b"/host/file", 1, 0), Err(Errno(13)));
}
#[test]
fn default_acl_replaces_guest_umask_for_native_mkdir_and_open_creation() {
    let root = Fixture::new();
    let mut v = root.vfs(false);
    let bytes = value(USER, GROUP);
    set(&mut v, b"/host", acl::DEFAULT, Some(&bytes), 0).unwrap();
    v.set_umask(0o077);
    v.mkdir_at(AT_FDCWD, b"/host/child", 0o777).unwrap();
    let fd = v
        .open_at(AT_FDCWD, b"/host/child/file", O_CREAT | 2, 0o640)
        .unwrap();
    v.close(fd).unwrap();
    assert_eq!(mode(&v, b"/host/child"), 0o770);
    assert_eq!(mode(&v, b"/host/child/file"), 0o640);
    assert_eq!(
        v.get_xattr(AT_FDCWD, Some(b"/host/child"), true, acl::DEFAULT),
        Ok(bytes)
    );
    v.credentials = Credentials::user(USER, USER);
    assert!(v.open_at(AT_FDCWD, b"/host/child/file", 0, 0).is_ok());
    assert_eq!(
        v.open_at(AT_FDCWD, b"/host/child/file", 1, 0),
        Err(Errno(13))
    );
}
#[test]
fn chmod_changes_the_native_acl_mask_and_independent_host_chmod_refreshes_guest_dac() {
    let root = Fixture::new();
    std::fs::write(root.0.join("file"), b"data").unwrap();
    let mut v = root.vfs(false);
    set(
        &mut v,
        b"/host/file",
        acl::ACCESS,
        Some(&value(USER, GROUP)),
        0,
    )
    .unwrap();
    let mut user = v.clone();
    user.credentials = Credentials::user(USER, USER);
    assert!(user.open_at(AT_FDCWD, b"/host/file", 0, 0).is_ok());
    v.chmod_at(AT_FDCWD, b"/host/file", 0o600).unwrap();
    assert_eq!(user.open_at(AT_FDCWD, b"/host/file", 0, 0), Err(Errno(13)));
    std::fs::set_permissions(root.0.join("file"), std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(user.open_at(AT_FDCWD, b"/host/file", 0, 0).is_ok());
    assert_eq!(user.open_at(AT_FDCWD, b"/host/file", 1, 0), Err(Errno(13)));
}
#[test]
fn original_acl_target_survives_close_reuse_rename_and_unlink() {
    let root = Fixture::new();
    std::fs::write(root.0.join("file"), b"original").unwrap();
    std::fs::write(root.0.join("other"), b"other").unwrap();
    let mut v = root.vfs(false);
    let fd = v.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap();
    let open = v.descriptor(fd).unwrap().open;
    let target = {
        let open = open.borrow();
        xattr::XattrTarget::new(
            open.node.clone().unwrap(),
            open.host_file.clone().unwrap(),
            open.mount.as_deref(),
            None,
            true,
        )
        .unwrap()
    };
    drop(open);
    v.close(fd).unwrap();
    assert_eq!(v.open_at(AT_FDCWD, b"/host/other", 0, 0).unwrap(), fd);
    std::fs::rename(root.0.join("file"), root.0.join("old")).unwrap();
    std::fs::write(root.0.join("file"), b"replacement").unwrap();
    let bytes = value(USER, GROUP);
    target.write(&v, acl::ACCESS, Some(&bytes), 0).unwrap();
    std::fs::remove_file(root.0.join("old")).unwrap();
    assert!(
        matches!(target.read(&v, Some(acl::ACCESS), 65536), Ok(FileValue::Bytes(actual)) if actual == bytes)
    );
    assert_eq!(
        v.get_xattr(fd as i32, None, true, acl::ACCESS),
        Err(Errno(61))
    );
    assert_eq!(
        v.get_xattr(AT_FDCWD, Some(b"/host/file"), true, acl::ACCESS),
        Err(Errno(61))
    );
}
#[test]
fn native_acl_maps_guest_namespace_ids_and_reports_unmapped_read_ids() {
    use crate::user_namespace::{MapFile, MapKind};
    let root = Fixture::new();
    std::fs::write(root.0.join("file"), b"data").unwrap();
    let mut v = root.vfs(false);
    let parent = v.credentials.clone();
    v.unshare_user().unwrap();
    for (kind, bytes) in [
        (MapKind::Uid, format!("0 0 1\n7 {USER} 1")),
        (MapKind::Gid, format!("0 0 1\n8 {GROUP} 1")),
    ] {
        MapFile::new(v.credentials.user_namespace.clone(), parent.clone(), kind)
            .write(bytes.as_bytes(), 0, &parent)
            .unwrap();
    }
    set(&mut v, b"/host/file", acl::ACCESS, Some(&value(7, 8)), 0).unwrap();
    assert_eq!(
        v.get_xattr(AT_FDCWD, Some(b"/host/file"), true, acl::ACCESS),
        Ok(value(7, 8))
    );
    let mut initial = v.clone();
    initial.credentials = parent;
    assert_eq!(
        initial.get_xattr(AT_FDCWD, Some(b"/host/file"), true, acl::ACCESS),
        Ok(value(USER, GROUP))
    );
    set(
        &mut initial,
        b"/host/file",
        acl::ACCESS,
        Some(&value(USER + 2, GROUP)),
        0,
    )
    .unwrap();
    let bytes = v
        .get_xattr(AT_FDCWD, Some(b"/host/file"), true, acl::ACCESS)
        .unwrap();
    assert_eq!(&bytes[16..20], &u32::MAX.to_le_bytes());
    assert_eq!(
        set(&mut v, b"/host/file", acl::ACCESS, Some(&value(99, 8)), 0),
        Err(Errno(22))
    );
}
#[test]
fn acl_flags_queries_permission_and_readonly_checks_use_posix_acl_rules() {
    let root = Fixture::new();
    std::fs::write(root.0.join("file"), b"data").unwrap();
    let mut v = root.vfs(false);
    let bytes = value(USER, GROUP);
    for flags in [2, 1, 3] {
        set(&mut v, b"/host/file", acl::ACCESS, Some(&bytes), flags).unwrap();
    }
    assert!(
        matches!(v.read_xattrs(AT_FDCWD, Some(b"/host/file"), true, Some(acl::ACCESS), 0),
        Ok(FileValue::Count(n)) if n == bytes.len() as u64)
    );
    assert!(matches!(
        v.read_xattrs(AT_FDCWD, Some(b"/host/file"), true, Some(acl::ACCESS), 1),
        Err(Errno(34))
    ));
    assert_eq!(
        set(&mut v, b"/host/file", acl::DEFAULT, Some(&bytes), 0),
        Err(Errno(13))
    );
    assert_eq!(
        set(&mut v, b"/host/file", acl::DEFAULT, Some(&[]), 0),
        Ok(())
    );
    let mut readonly = root.vfs(true);
    assert_eq!(
        set(&mut readonly, b"/host/file", acl::ACCESS, Some(&bytes), 0),
        Err(Errno(30))
    );
    v.credentials = Credentials::user(USER, USER);
    assert_eq!(
        set(&mut v, b"/host/file", acl::ACCESS, Some(&bytes), 0),
        Err(Errno(1))
    );
}
#[test]
fn grant_owner_substitution_is_used_in_native_acl_bytes_and_colliding_ids_are_rejected() {
    let root = Fixture::new();
    std::fs::write(root.0.join("file"), b"data").unwrap();
    let mut v = Vfs::default();
    v.mkdir_at(AT_FDCWD, b"/host", 0o755).unwrap();
    v.credentials.fsuid = USER;
    v.credentials.fsgid = GROUP;
    v.mount_host(b"/host", &root.0, false).unwrap();
    let bytes = value(USER, GROUP);
    set(&mut v, b"/host/file", acl::ACCESS, Some(&bytes), 0).unwrap();
    let native = File::open(root.0.join("file")).unwrap();
    let mut raw = [0; 128];
    let count = xattr::Native::from_file(&native)
        .unwrap()
        .read(Some(&CString::new(acl::ACCESS).unwrap()), &mut raw)
        .unwrap();
    assert_eq!(count, bytes.len());
    // SAFETY: scalar host identity queries with no pointers or side effects.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    assert_eq!(&raw[16..20], &uid.to_le_bytes());
    assert_eq!(&raw[32..36], &gid.to_le_bytes());
    assert_eq!(
        v.get_xattr(AT_FDCWD, Some(b"/host/file"), true, acl::ACCESS),
        Ok(bytes)
    );
    if uid != USER {
        assert_eq!(
            set(
                &mut v,
                b"/host/file",
                acl::ACCESS,
                Some(&value(uid, GROUP)),
                0
            ),
            Err(Errno(22))
        );
        let fd = v.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap();
        assert_eq!(v.chown_fd(fd, uid, u32::MAX), Err(Errno(22)));
        xattr::Native::from_file(&native)
            .unwrap()
            .write(
                &CString::new(acl::ACCESS).unwrap(),
                Some(&value(USER, GROUP)),
                0,
            )
            .unwrap();
        assert_eq!(
            v.get_xattr(fd as i32, None, true, acl::ACCESS),
            Err(Errno(75))
        );
    }
}
#[test]
fn exec_by_retained_fd_refreshes_native_acl_before_the_execute_permission_check() {
    let root = Fixture::new();
    std::fs::write(root.0.join("file"), b"program").unwrap();
    let mut v = root.vfs(false);
    set(
        &mut v,
        b"/host/file",
        acl::ACCESS,
        Some(&value(USER, GROUP)),
        0,
    )
    .unwrap();
    let fd = v.open_at(AT_FDCWD, b"/host/file", O_PATH, 0).unwrap();
    v.credentials = Credentials::user(USER, USER);
    assert!(v.executable_file_at(fd as i32, b"", 0x1000).is_ok());
    std::fs::set_permissions(root.0.join("file"), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        v.executable_file_at(fd as i32, b"", 0x1000),
        Err(Errno(13))
    ));
}
