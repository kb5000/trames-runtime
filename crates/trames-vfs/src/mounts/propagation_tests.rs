// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
const SHARED: u64 = 1 << 20;
const PRIVATE: u64 = 1 << 18;
const SLAVE: u64 = 1 << 19;
fn setup() -> Vfs {
    let mut v = Vfs::default();
    for path in [b"/src".as_slice(), b"/peer", b"/slave", b"/private"] {
        v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
    }
    v.mount(None, b"/src", Some(b"tmpfs"), 0, None).unwrap();
    v.mount(None, b"/src", None, SHARED, None).unwrap();
    for path in [b"/peer".as_slice(), b"/slave", b"/private"] {
        v.mount(Some(b"/src"), path, None, 4096, None).unwrap();
    }
    v.mount(None, b"/slave", None, SLAVE, None).unwrap();
    v.mount(None, b"/private", None, PRIVATE, None).unwrap();
    v
}
fn device(v: &Vfs, p: &[u8]) -> u64 {
    u64::from_le_bytes(v.stat_at(AT_FDCWD, p).unwrap()[..8].try_into().unwrap())
}
fn write(v: &mut Vfs, p: &[u8], bytes: &[u8]) {
    let fd = v.open_at(AT_FDCWD, p, 0x41, 0o644).unwrap();
    v.write(fd, bytes).unwrap();
    v.close(fd).unwrap();
}
fn read(v: &mut Vfs, p: &[u8]) -> Result<Vec<u8>> {
    let fd = v.open_at(AT_FDCWD, p, 0, 0)?;
    let value = v.read(fd, 1024);
    v.close(fd)?;
    value
}
#[test]
fn shared_peer_slave_and_private_mounts_have_real_one_way_visibility() {
    let mut v = setup();
    v.mkdir_at(AT_FDCWD, b"/src/sub", 0o755).unwrap();
    let underlying = device(&v, b"/private/sub");
    v.mount(None, b"/src/sub", Some(b"tmpfs"), 0, None).unwrap();
    let actual = device(&v, b"/src/sub");
    assert_ne!(actual, underlying);
    assert_eq!(device(&v, b"/peer/sub"), actual);
    assert_eq!(device(&v, b"/slave/sub"), actual);
    assert_eq!(device(&v, b"/private/sub"), underlying);
    let busy = v.open_at(AT_FDCWD, b"/peer/sub", O_DIRECTORY, 0).unwrap();
    assert_eq!(v.umount(b"/src/sub", 0), Err(Errno(16)));
    assert_eq!(device(&v, b"/src/sub"), actual);
    assert_eq!(device(&v, b"/slave/sub"), actual);
    v.close(busy).unwrap();
    write(&mut v, b"/src/sub/value", b"original");
    assert_eq!(read(&mut v, b"/slave/sub/value").unwrap(), b"original");
    assert_eq!(read(&mut v, b"/private/sub/value"), Err(Errno(2)));
    v.umount(b"/slave/sub", 0).unwrap();
    assert_eq!(device(&v, b"/slave/sub"), underlying);
    assert_eq!(device(&v, b"/src/sub"), actual);
    v.umount(b"/src/sub", 0).unwrap();
    assert_eq!(device(&v, b"/peer/sub"), underlying);
    v.mkdir_at(AT_FDCWD, b"/slave/local", 0o755).unwrap();
    v.mount(None, b"/slave/local", Some(b"tmpfs"), 0, None)
        .unwrap();
    assert_ne!(device(&v, b"/slave/local"), device(&v, b"/src/local"));
}
#[test]
fn namespace_clone_preserves_peers_then_recursive_private_detaches_them() {
    let mut parent = setup();
    parent.mkdir_at(AT_FDCWD, b"/src/sub", 0o755).unwrap();
    let mut child = parent.clone();
    child.unshare_mounts().unwrap();
    assert!(Arc::ptr_eq(
        &parent.mount_admin().unwrap(),
        &child.mount_admin().unwrap()
    ));
    let observer = parent.path_queries();
    child
        .mount(None, b"/src/sub", Some(b"tmpfs"), 0, None)
        .unwrap();
    assert_eq!(device(&parent, b"/src/sub"), device(&child, b"/peer/sub"));
    assert_eq!(
        device(&observer.view.borrow(), b"/src/sub"),
        device(&child, b"/src/sub")
    );
    parent
        .mount(None, b"/", None, PRIVATE | 16384, None)
        .unwrap();
    let old = device(&parent, b"/src/sub");
    child.umount(b"/src/sub", 0).unwrap();
    assert_eq!(device(&parent, b"/src/sub"), old);
    assert_ne!(device(&child, b"/src/sub"), old);
    let mut independent = parent.clone();
    independent.unshare_mounts().unwrap();
    assert!(!Arc::ptr_eq(
        &parent.mount_admin().unwrap(),
        &independent.mount_admin().unwrap()
    ));
}
#[test]
fn shared_slave_group_relays_events_downstream_but_not_back_up() {
    let mut parent = setup();
    parent.mount(None, b"/slave", None, SHARED, None).unwrap();
    let mut child = parent.clone();
    child.unshare_mounts().unwrap();
    parent.mkdir_at(AT_FDCWD, b"/src/down", 0o755).unwrap();
    parent
        .mount(None, b"/src/down", Some(b"tmpfs"), 0, None)
        .unwrap();
    assert_eq!(
        device(&parent, b"/src/down"),
        device(&child, b"/slave/down")
    );
    child.mkdir_at(AT_FDCWD, b"/slave/local", 0o755).unwrap();
    child
        .mount(None, b"/slave/local", Some(b"tmpfs"), 0, None)
        .unwrap();
    assert_eq!(
        device(&child, b"/slave/local"),
        device(&parent, b"/slave/local")
    );
    assert_ne!(
        device(&parent, b"/src/local"),
        device(&parent, b"/slave/local")
    );
    child.umount(b"/slave/down", 0).unwrap();
    assert_ne!(
        device(&parent, b"/slave/down"),
        device(&parent, b"/src/down")
    );
}
#[test]
fn propagation_metadata_does_not_retain_dead_namespaces() {
    let v = setup();
    let mut child = v.clone();
    child.unshare_mounts().unwrap();
    let weak = Arc::downgrade(&child.mounts.as_ref().unwrap().0);
    drop(child);
    assert!(weak.upgrade().is_none());
    let mut next = v.clone();
    next.unshare_mounts().unwrap();
    assert_eq!(next.mount_admin().unwrap().namespaces().len(), 2);
}
#[test]
fn downstream_slave_reparents_when_its_last_immediate_master_disappears() {
    let mut v = setup();
    v.mkdir_at(AT_FDCWD, b"/downstream", 0o755).unwrap();
    v.mount(None, b"/slave", None, SHARED, None).unwrap();
    v.mount(Some(b"/slave"), b"/downstream", None, 4096, None)
        .unwrap();
    v.mount(None, b"/downstream", None, SLAVE, None).unwrap();
    v.umount(b"/slave", 0).unwrap();
    v.mkdir_at(AT_FDCWD, b"/src/after", 0o755).unwrap();
    v.mount(None, b"/src/after", Some(b"tmpfs"), 0, None)
        .unwrap();
    assert_eq!(device(&v, b"/src/after"), device(&v, b"/downstream/after"));
}
#[test]
fn tmpfs_owners_are_guest_ids_and_invalid_ids_do_not_publish_a_mount() {
    let mut v = setup();
    let before = v.mounts.as_ref().unwrap().0.borrow().mounts.len();
    for options in [b"uid=-1".as_slice(), b"gid=4294967295", b"uid=4294967296"] {
        assert_eq!(
            v.mount(None, b"/private", Some(b"tmpfs"), 0, Some(options)),
            Err(Errno(22))
        );
    }
    assert_eq!(v.mounts.as_ref().unwrap().0.borrow().mounts.len(), before);
    v.mount(
        None,
        b"/private",
        Some(b"tmpfs"),
        14,
        Some(b"mode=750,uid=1000,gid=1007"),
    )
    .unwrap();
    let s = v.stat_at(AT_FDCWD, b"/private").unwrap();
    assert_eq!(u32::from_le_bytes(s[24..28].try_into().unwrap()), 1000);
    assert_eq!(u32::from_le_bytes(s[28..32].try_into().unwrap()), 1007);
    assert_eq!(
        u32::from_le_bytes(s[16..20].try_into().unwrap()) & 0o7777,
        0o750
    );
}
