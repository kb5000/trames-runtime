// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

#[test]
fn empty_readlink_retains_the_unlinked_path_without_extending_the_original_fd() {
    let mut v = Vfs::default();
    v.symlink_at(b"accepted target", AT_FDCWD, b"/link")
        .unwrap();
    let fd = v
        .open_at(AT_FDCWD, b"/link", O_PATH | O_NOFOLLOW, 0)
        .unwrap();
    let original = v.shared_files().lookup(fd).unwrap().unwrap();
    let ofd = Arc::downgrade(&original.open);
    let inode = Arc::downgrade(original.open.node.as_ref().unwrap());
    let reply = FileReply::capture(|| v.readlink_at(fd as i32, b"").map(FileValue::Bytes));
    v.unlink_at(AT_FDCWD, b"/link", false).unwrap();
    v.close(fd).unwrap();
    drop(original);
    assert!(
        ofd.upgrade().is_none(),
        "readlink holds a path, not the lookup FD"
    );
    assert!(
        inode.upgrade().is_some(),
        "accepted output still owns the deleted symlink"
    );
    let FileReply {
        result, resources, ..
    } = reply;
    drop(resources);
    assert!(inode.upgrade().is_none());
    assert_eq!(result.unwrap().into_bytes().unwrap(), b"accepted target");
}

#[test]
fn fd_xattr_holds_its_original_ofd_until_output_finishes_and_errors_release_it() {
    for missing in [false, true] {
        let mut v = Vfs::default();
        v.import_file(b"/file", b"data".to_vec()).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/file", 2, 0).unwrap();
        v.set_xattr(fd as i32, None, true, b"user.note", Some(b"value"), 0)
            .unwrap();
        let original = v.shared_files().lookup(fd).unwrap().unwrap();
        let ofd = Arc::downgrade(&original.open);
        let name = if missing {
            &b"user.missing"[..]
        } else {
            &b"user.note"[..]
        };
        let reply = FileReply::capture(|| v.read_xattrs(fd as i32, None, true, Some(name), 64));
        v.close(fd).unwrap();
        drop(original);
        assert_eq!(ofd.upgrade().is_some(), !missing);
        let FileReply {
            result, resources, ..
        } = reply;
        drop(resources);
        assert!(ofd.upgrade().is_none());
        if missing {
            assert!(matches!(result, Err(Errno(61))));
        } else {
            assert_eq!(result.unwrap().into_bytes().unwrap(), b"value");
        }
    }
}

#[test]
fn nested_output_calls_restore_the_outer_original_resource_collection() {
    let mut v = Vfs::default();
    v.symlink_at(b"first", AT_FDCWD, b"/first").unwrap();
    v.symlink_at(b"second", AT_FDCWD, b"/second").unwrap();
    let first = v.metadata_target(AT_FDCWD, b"/first", false).unwrap().node;
    let second = v.metadata_target(AT_FDCWD, b"/second", false).unwrap().node;
    let first_weak = Arc::downgrade(&first);
    let second_weak = Arc::downgrade(&second);
    drop((first, second));
    let mut inner = None;
    let outer = FileReply::capture(|| {
        inner = Some(FileReply::capture(|| {
            v.readlink_at(AT_FDCWD, b"/second").map(FileValue::Bytes)
        }));
        v.readlink_at(AT_FDCWD, b"/first").map(FileValue::Bytes)
    });
    v.unlink_at(AT_FDCWD, b"/first", false).unwrap();
    v.unlink_at(AT_FDCWD, b"/second", false).unwrap();
    assert!(first_weak.upgrade().is_some());
    assert!(second_weak.upgrade().is_some());
    drop(inner);
    assert!(first_weak.upgrade().is_some());
    assert!(second_weak.upgrade().is_none());
    drop(outer);
    assert!(first_weak.upgrade().is_none());
}
