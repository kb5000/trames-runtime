// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
fn mode_of(v: &Vfs, path: &[u8]) -> u32 {
    let s = v.stat_at(AT_FDCWD, path).unwrap();
    u32::from_le_bytes(s[16..20].try_into().unwrap())
}
fn value(named: u32) -> Vec<u8> {
    let mut bytes = 2u32.to_le_bytes().to_vec();
    for (tag, p, id) in [
        (1u16, 7u16, u32::MAX),
        (2, 7, named),
        (4, 0, u32::MAX),
        (8, 4, 2000),
        (16, 7, u32::MAX),
        (32, 0, u32::MAX),
    ] {
        bytes.extend(tag.to_le_bytes());
        bytes.extend(p.to_le_bytes());
        bytes.extend(id.to_le_bytes());
    }
    bytes
}
#[test]
fn inherited_acl_uses_creation_mode_not_umask_and_chmod_changes_the_mask() {
    let mut v = Vfs::default();
    v.mkdir_at(AT_FDCWD, b"/parent", 0o777).unwrap();
    v.set_xattr(
        AT_FDCWD,
        Some(b"/parent"),
        true,
        DEFAULT,
        Some(&value(1000)),
        0,
    )
    .unwrap();
    v.set_umask(0o077);
    v.mkdir_at(AT_FDCWD, b"/parent/child", 0o777).unwrap();
    let fd = v
        .open_at(AT_FDCWD, b"/parent/child/file", 0o102, 0o640)
        .unwrap();
    v.close(fd).unwrap();
    assert_eq!(mode_of(&v, b"/parent/child/file") & 0o777, 0o640);
    assert_eq!(
        v.get_xattr(AT_FDCWD, Some(b"/parent/child"), true, DEFAULT)
            .unwrap(),
        value(1000)
    );
    let mut user = v.clone();
    user.credentials = Credentials::user(1000, 1000);
    assert!(user.open_at(AT_FDCWD, b"/parent/child/file", 0, 0).is_ok());
    assert_eq!(
        user.open_at(AT_FDCWD, b"/parent/child/file", 1, 0),
        Err(Errno(13))
    );
    v.chmod_at(AT_FDCWD, b"/parent/child/file", 0o600).unwrap();
    assert_eq!(
        user.open_at(AT_FDCWD, b"/parent/child/file", 0, 0),
        Err(Errno(13))
    );
    assert_eq!(
        user.set_xattr(
            AT_FDCWD,
            Some(b"/parent/child/file"),
            true,
            ACCESS,
            Some(&value(1000)),
            0
        ),
        Err(Errno(1))
    );
    let fd = v.open_at(AT_FDCWD, b"/plain", 0o102, 0o666).unwrap();
    v.close(fd).unwrap();
    assert_eq!(mode_of(&v, b"/plain") & 0o777, 0o600);
}
#[test]
fn malformed_acl_does_not_change_inode_and_equivalent_access_acl_updates_mode() {
    let mut v = Vfs::default();
    v.mkdir_at(AT_FDCWD, b"/dir", 0o755).unwrap();
    let before = mode_of(&v, b"/dir");
    let mut bad = value(1000);
    bad[6] = 8;
    assert_eq!(
        v.set_xattr(AT_FDCWD, Some(b"/dir"), true, ACCESS, Some(&bad), 0),
        Err(Errno(22))
    );
    assert_eq!(mode_of(&v, b"/dir"), before);
    let mut simple = 2u32.to_le_bytes().to_vec();
    for (tag, p) in [(1u16, 7u16), (4, 5), (32, 1)] {
        simple.extend(tag.to_le_bytes());
        simple.extend(p.to_le_bytes());
        simple.extend(u32::MAX.to_le_bytes());
    }
    v.set_xattr(AT_FDCWD, Some(b"/dir"), true, ACCESS, Some(&simple), 0)
        .unwrap();
    assert_eq!(mode_of(&v, b"/dir") & 0o777, 0o751);
    assert_eq!(
        v.get_xattr(AT_FDCWD, Some(b"/dir"), true, ACCESS),
        Err(Errno(61))
    );
}
