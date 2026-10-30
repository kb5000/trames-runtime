// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
#[test]
#[ignore = "emits the independent iOS File Provider manifest fixture"]
fn emit_file_provider_manifest_fixture() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_reader(b"/root/readme.txt", &mut &b"rootfs fixture"[..], false)
        .unwrap();
    v.link_at(AT_FDCWD, b"/root/readme.txt", AT_FDCWD, b"/alias")
        .unwrap();
    v.symlink_at(b"/root/readme.txt", AT_FDCWD, b"/link")
        .unwrap();
    v.set_xattr(
        AT_FDCWD,
        Some(b"/alias"),
        true,
        b"user.test",
        Some(b"metadata"),
        0,
    )
    .unwrap();
    v.sync().unwrap();
    drop(v);
    let path = std::env::var("TRAMES_PROVIDER_FIXTURE").expect("TRAMES_PROVIDER_FIXTURE");
    let bytes = fs::read(dir.0.join("manifest")).unwrap();
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    fs::write(path, hex + "\n").unwrap();
    // The fixture is produced and reopened by the production Rust format.
    let mut reopened = dir.open();
    let fd = reopened.open_at(AT_FDCWD, b"/alias", 0, 0).unwrap();
    assert_eq!(reopened.pread(fd, 32, 0).unwrap(), b"rootfs fixture");
}
#[test]
fn repeated_host_import_is_atomic_preserves_open_inode_and_survives_cancel() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_reader(b"/upload", &mut &b"original"[..], true)
        .unwrap();
    let old = v.open_at(AT_FDCWD, b"/upload", 0, 0).unwrap();
    struct Cancel;
    impl std::io::Read for Cancel {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::Interrupted.into())
        }
    }
    assert_eq!(
        v.import_reader_replace(b"/upload", &mut Cancel),
        Err(Errno(4))
    );
    assert_eq!(v.executable(b"/upload").unwrap(), b"original");
    v.import_reader_replace(b"/upload", &mut &b"replacement"[..])
        .unwrap();
    assert_eq!(v.executable(b"/upload").unwrap(), b"replacement");
    assert_eq!(v.read(old, 32).unwrap(), b"original");
    v.close(old).unwrap();
    drop(v);
    let reopened = dir.open();
    assert_eq!(reopened.executable(b"/upload").unwrap(), b"replacement");
}
#[test]
fn inode_attributes_persist_share_hardlinks_and_rollback_failed_commits() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_file(b"/attrs", b"payload".to_vec()).unwrap();
    v.link_at(AT_FDCWD, b"/attrs", AT_FDCWD, b"/alias").unwrap();
    v.set_xattr(
        AT_FDCWD,
        Some(b"/attrs"),
        true,
        b"user.key",
        Some(b"a\0b"),
        1,
    )
    .unwrap();
    assert_eq!(
        v.get_xattr(AT_FDCWD, Some(b"/alias"), true, b"user.key")
            .unwrap(),
        b"a\0b"
    );
    let before = v.stat_at(AT_FDCWD, b"/attrs").unwrap();
    fs::create_dir(dir.0.join("manifest.new")).unwrap();
    assert!(v
        .set_xattr(
            AT_FDCWD,
            Some(b"/attrs"),
            true,
            b"user.key",
            Some(b"replacement"),
            2
        )
        .is_err());
    assert_eq!(v.stat_at(AT_FDCWD, b"/attrs").unwrap(), before);
    assert_eq!(
        v.get_xattr(AT_FDCWD, Some(b"/alias"), true, b"user.key")
            .unwrap(),
        b"a\0b"
    );
    fs::remove_dir(dir.0.join("manifest.new")).unwrap();
    v.sync().unwrap();
    drop(v);
    let mut v = dir.open();
    assert_eq!(
        v.get_xattr(AT_FDCWD, Some(b"/alias"), true, b"user.key")
            .unwrap(),
        b"a\0b"
    );
    let fd = v.open_at(AT_FDCWD, b"/attrs", 0, 0).unwrap();
    v.unlink_at(AT_FDCWD, b"/attrs", false).unwrap();
    v.unlink_at(AT_FDCWD, b"/alias", false).unwrap();
    assert_eq!(
        v.get_xattr(fd as i32, None, true, b"user.key").unwrap(),
        b"a\0b"
    );
    v.close(fd).unwrap();
}

#[test]
fn inode_attributes_bound_metadata_and_reject_unimplemented_security_policy() {
    let mut v = Vfs::default();
    let value = vec![9; 65000];
    for i in 0..17 {
        let path = format!("/attrs-{i}");
        v.import_file(path.as_bytes(), vec![]).unwrap();
        let result = v.set_xattr(
            AT_FDCWD,
            Some(path.as_bytes()),
            true,
            b"user.key",
            Some(&value),
            0,
        );
        assert_eq!(result, if i == 16 { Err(Errno(28)) } else { Ok(()) });
    }
    assert_eq!(
        v.get_xattr(AT_FDCWD, Some(b"/attrs-16"), true, b"user.key"),
        Err(Errno(61))
    );
    assert_eq!(
        v.set_xattr(
            AT_FDCWD,
            Some(b"/attrs-0"),
            true,
            b"user.large",
            Some(&vec![0; 65536]),
            0
        ),
        Err(Errno(28))
    );
    assert_eq!(
        v.get_xattr(AT_FDCWD, Some(b"/attrs-0"), true, b"user.key")
            .unwrap(),
        value
    );
    assert_eq!(
        v.get_xattr(AT_FDCWD, Some(b"/attrs-0"), true, b"security.capability"),
        Err(Errno(61))
    );
    assert_eq!(
        v.set_xattr(
            AT_FDCWD,
            Some(b"/attrs-0"),
            true,
            b"security.capability",
            Some(&[0; 20]),
            0
        ),
        Err(Errno(95))
    );
    v.set_xattr(AT_FDCWD, Some(b"/attrs-0"), true, b"user.key", None, 0)
        .unwrap();
    v.set_xattr(
        AT_FDCWD,
        Some(b"/attrs-16"),
        true,
        b"user.key",
        Some(&value),
        0,
    )
    .unwrap();
}

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "trames-store-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn open(&self) -> Vfs {
        Vfs::open_disk(&self.0, DiskOptions::default()).unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn size(stat: [u8; 128]) -> u64 {
    u64::from_le_bytes(stat[48..56].try_into().unwrap())
}
#[test]
fn disk_read_lease_retains_unlinked_object_and_store_without_vfs() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_file(b"/data", b"payload".to_vec()).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
    let (read, job) = v.prepare_disk_read(fd, 32, None).unwrap().unwrap();
    v.unlink_at(AT_FDCWD, b"/data", false).unwrap();
    v.close(fd).unwrap();
    drop(read);
    drop(v);
    // Neither a guest FD nor a coordinator capability is needed to keep the
    // private object safe until a job sent to a different host thread finishes.
    assert!(matches!(
        Vfs::open_disk(&dir.0, DiskOptions::default()),
        Err(Errno(16))
    ));
    let bytes = std::thread::spawn(move || job.run())
        .join()
        .unwrap()
        .unwrap();
    assert_eq!(bytes, b"payload");
    let reopened = dir.open();
    assert_eq!(reopened.stat_at(AT_FDCWD, b"/data"), Err(Errno(2)));
}
#[test]
fn disk_sync_jobs_share_one_manifest_transaction_and_retain_original_resources() {
    fn send<T: Send>() {}
    send::<DiskSyncJob>();
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_file(b"/data", b"payload".to_vec()).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/data", 2, 0).unwrap();
    v.pwrite(fd, b"updated", 0).unwrap();
    let (first, a) = v.prepare_disk_sync(fd, false).unwrap().unwrap();
    let (second, b) = v.prepare_disk_sync(fd, true).unwrap().unwrap();
    v.close(fd).unwrap();
    let reused = v.open_at(AT_FDCWD, b"/other", 0x42, 0o600).unwrap();
    assert_eq!(fd, reused);
    v.write(reused, b"other").unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let ready = barrier.clone();
    let worker = std::thread::spawn(move || { ready.wait(); a.run() });
    barrier.wait();
    b.run().unwrap();
    worker.join().unwrap().unwrap();
    drop((first, second, v));
    let mut reopened = dir.open();
    let fd = reopened.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
    assert_eq!(reopened.read(fd, 32).unwrap(), b"updated");
    let fd = reopened.open_at(AT_FDCWD, b"/other", 0, 0).unwrap();
    assert_eq!(reopened.read(fd, 32).unwrap(), b"other");
}
#[test]
fn disk_sync_admission_keeps_ram_and_mapped_writeback_on_original_path() {
    let mut ram = Vfs::default();
    let fd = ram.open_at(AT_FDCWD, b"/ram", 0x42, 0o600).unwrap();
    assert!(ram.prepare_disk_sync(fd, false).unwrap().is_none());
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_file(b"/mapped", vec![0; 4096]).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/mapped", 2, 0).unwrap();
    let mappings = v.mapping_pages(fd, 0, 4096, true, true).unwrap();
    mappings[0].write(0, b"mapped").unwrap();
    assert!(v.prepare_disk_sync(fd, false).unwrap().is_none());
    v.sync_fd(fd, false).unwrap();
    assert_eq!(v.pread(fd, 6, 0).unwrap(), b"mapped");
}
#[test]
fn disk_read_offsets_conflicts_short_reads_and_errors_commit_once() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_file(b"/data", b"abcdef".to_vec()).unwrap();
    v.link_at(AT_FDCWD, b"/data", AT_FDCWD, b"/alias").unwrap();
    let fd = v.open_at(AT_FDCWD, b"/data", 2, 0).unwrap();
    let dup = v.dup(fd, 0, false).unwrap();
    let alias = v.open_at(AT_FDCWD, b"/alias", 2, 0).unwrap();
    let (read, job) = v.prepare_disk_read(fd, 4, None).unwrap().unwrap();
    assert!(read.conflicts(&v, dup, 63));
    assert!(read.conflicts(&v, alias, 68));
    assert!(!read.conflicts(&v, alias, 67));
    assert_eq!(read.finish(job.run()).unwrap(), b"abcd");
    assert_eq!(v.seek(dup, 0, 1).unwrap(), 4);
    let (read, job) = v.prepare_disk_read(fd, 100, Some(5)).unwrap().unwrap();
    assert_eq!(read.finish(job.run()).unwrap(), b"f");
    assert_eq!(v.seek(dup, 0, 1).unwrap(), 4);
    let (read, job) = v.prepare_disk_read(fd, 100, None).unwrap().unwrap();
    drop(job);
    assert_eq!(read.finish(Err(Errno(5))), Err(Errno(5)));
    assert_eq!(v.seek(dup, 0, 1).unwrap(), 4);
    assert!(v.prepare_disk_read(fd, 0, None).unwrap().is_none());
    assert!(v.prepare_disk_read(fd, 4, Some(100)).unwrap().is_none());
}
#[test]
fn cached_disk_handles_observe_writes_truncate_and_recycled_short_reads() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_file(b"/data", vec![0xa5; 32768]).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/data", 2, 0).unwrap();
    let mut cache = DiskReadCache::default();
    let (read, job) = v.prepare_disk_read(fd, 32768, Some(0)).unwrap().unwrap();
    let bytes = read.finish(job.run_cached(&mut cache, Vec::new())).unwrap();
    let allocation = bytes.as_ptr();
    v.pwrite(fd, b"new", 0).unwrap();
    let (read, job) = v.prepare_disk_read(fd, 32768, Some(0)).unwrap().unwrap();
    let bytes = read.finish(job.run_cached(&mut cache, bytes)).unwrap();
    assert_eq!(bytes.as_ptr(), allocation);
    assert_eq!(&bytes[..3], b"new");
    v.truncate_fd(fd, 1).unwrap();
    let (read, job) = v.prepare_disk_read(fd, 32768, Some(0)).unwrap().unwrap();
    let bytes = read.finish(job.run_cached(&mut cache, bytes)).unwrap();
    assert_eq!(bytes, b"n");
    v.truncate_fd(fd, 32768).unwrap();
    let (read, job) = v.prepare_disk_read(fd, 32768, Some(0)).unwrap().unwrap();
    let bytes = read.finish(job.run_cached(&mut cache, bytes)).unwrap();
    assert_eq!(bytes.as_ptr(), allocation);
    assert_eq!(bytes[0], b'n');
    assert!(bytes[1..].iter().all(|b| *b == 0));
}
#[test]
fn cached_handles_do_not_retain_store_lock_or_confuse_replaced_inodes() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_file(b"/data", b"old".to_vec()).unwrap();
    let old = v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
    let mut cache = DiskReadCache::default();
    let (read, job) = v.prepare_disk_read(old, 32, Some(0)).unwrap().unwrap();
    assert_eq!(
        read.finish(job.run_cached(&mut cache, Vec::new())).unwrap(),
        b"old"
    );
    v.import_reader_replace(b"/data", &mut &b"replacement"[..])
        .unwrap();
    let new = v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
    for (fd, expected) in [(new, &b"replacement"[..]), (old, &b"old"[..])] {
        let (read, job) = v.prepare_disk_read(fd, 32, Some(0)).unwrap().unwrap();
        assert_eq!(
            read.finish(job.run_cached(&mut cache, Vec::new())).unwrap(),
            expected
        );
    }
    drop(v);
    // Cache remains alive with weak identities/host read descriptors. It must
    // neither pin orphan paths/store locks nor authorize a future incarnation.
    let mut v = dir.open();
    let fd = v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
    let (read, job) = v.prepare_disk_read(fd, 32, Some(0)).unwrap().unwrap();
    assert_eq!(
        read.finish(job.run_cached(&mut cache, Vec::new())).unwrap(),
        b"replacement"
    );
}
#[test]
fn device_nodes_persist_numbers_links_and_driver_behavior() {
    let dir = Temp::new();
    let mut v = dir.open();
    let initial = v.capacity();
    let devices = [
        ("null", 0x103),
        ("zero", 0x105),
        ("full", 0x107),
        ("random", 0x108),
        ("urandom", 0x109),
        ("tty", 0x500),
        ("ptmx", 0x502),
        ("unknown", 0xffffffff),
    ];
    for (name, number) in devices {
        v.mknod_at(AT_FDCWD, format!("/{name}").as_bytes(), 0o20640, number)
            .unwrap();
    }
    v.mknod_at(AT_FDCWD, b"/block", 0o60600, 0x103).unwrap();
    v.link_at(AT_FDCWD, b"/zero", AT_FDCWD, b"/alias").unwrap();
    v.rename_at(AT_FDCWD, b"/zero", AT_FDCWD, b"/renamed", 0)
        .unwrap();
    v.chown_at(AT_FDCWD, b"/renamed", 123, 456, true).unwrap();
    let before = v.stat_at(AT_FDCWD, b"/renamed").unwrap();
    assert_eq!(v.capacity().used_bytes, initial.used_bytes);
    v.sync().unwrap();
    drop(v);
    let mut v = dir.open();
    let after = v.stat_at(AT_FDCWD, b"/alias").unwrap();
    assert_eq!(&before[..48], &after[..48]);
    assert_eq!(u64::from_le_bytes(after[32..40].try_into().unwrap()), 0x105);
    let fd = v.open_at(AT_FDCWD, b"/alias", 2, 0).unwrap();
    v.unlink_at(AT_FDCWD, b"/alias", false).unwrap();
    v.unlink_at(AT_FDCWD, b"/renamed", false).unwrap();
    assert_eq!(v.read(fd, 17).unwrap(), vec![0; 17]);
    assert_eq!(v.write(fd, b"discarded").unwrap(), 9);
    assert_eq!(v.seek(fd, 9, 0).unwrap(), 0);
    let null = v.open_at(AT_FDCWD, b"/null", 2, 0).unwrap();
    assert!(v.read(null, 17).unwrap().is_empty());
    assert_eq!(v.write(null, b"discarded").unwrap(), 9);
    let full = v.open_at(AT_FDCWD, b"/full", 2, 0).unwrap();
    assert_eq!(v.read(full, 17).unwrap(), vec![0; 17]);
    assert_eq!(v.write(full, b"x"), Err(Errno(28)));
    for name in [b"/random".as_slice(), b"/urandom"] {
        let fd = v.open_at(AT_FDCWD, name, 0, 0).unwrap();
        assert_eq!(v.read(fd, 17).unwrap().len(), 17);
    }
    for name in [b"/unknown".as_slice(), b"/block"] {
        assert_eq!(v.open_at(AT_FDCWD, name, 0, 0), Err(Errno(6)));
        let fd = v.open_at(AT_FDCWD, name, O_PATH, 0).unwrap();
        assert_eq!(v.stat_fd(fd).unwrap(), v.stat_at(AT_FDCWD, name).unwrap());
    }
    assert_eq!(fs::read_dir(dir.0.join("objects")).unwrap().count(), 0);
}
#[test]
fn device_creation_failure_rolls_back_and_unprivileged_cannot_create() {
    let dir = Temp::new();
    let mut v = dir.open();
    let before = v.capacity();
    fs::create_dir(dir.0.join("manifest.new")).unwrap();
    assert!(v.mknod_at(AT_FDCWD, b"/failed", 0o20666, 0x105).is_err());
    assert_eq!(v.stat_at(AT_FDCWD, b"/failed"), Err(Errno(2)));
    assert_eq!(v.capacity().nodes_used, before.nodes_used);
    fs::remove_dir(dir.0.join("manifest.new")).unwrap();
    v.set_runtime_info(1, RuntimeInfo::default());
    assert_eq!(
        v.link_at(AT_FDCWD, b"/dev/zero", AT_FDCWD, b"/pseudo-alias"),
        Err(Errno(1))
    );
    assert_eq!(v.stat_at(AT_FDCWD, b"/pseudo-alias"), Err(Errno(2)));
    v.credentials.caps.effective &= !(1 << capabilities::MKNOD);
    assert_eq!(
        v.mknod_at(AT_FDCWD, b"/denied", 0o20666, 0x103),
        Err(Errno(1))
    );
    assert_eq!(
        v.mknod_at(AT_FDCWD, b"/block", 0o60666, 0xfd01),
        Err(Errno(1))
    );
    // dev is ignored for regular files/FIFOs, which do not require MKNOD.
    v.mknod_at(AT_FDCWD, b"/regular", 0o100600, u64::MAX)
        .unwrap();
    v.mknod_at(AT_FDCWD, b"/fifo", 0o10600, u64::MAX).unwrap();
}
#[test]
fn corrupt_device_payloads_are_rejected_before_storage_recovery() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.mknod_at(AT_FDCWD, b"/zero", 0o20666, 0x105).unwrap();
    v.import_file(b"/keep", b"keep".to_vec()).unwrap();
    drop(v);
    let manifest = dir.0.join("manifest");
    let original = fs::read(&manifest).unwrap();
    let mut offset = 40;
    while original[offset + 20] != 6 {
        let size = u32::from_le_bytes(original[offset + 72..offset + 76].try_into().unwrap());
        offset += 76 + size as usize;
    }
    let orphan = dir.0.join("objects/ffffffffffffffff.dat");
    fs::write(&orphan, b"retain until manifest validates").unwrap();
    for field in [20, 21, 72] {
        let mut data = original.clone();
        data[offset + field] ^= 1; // wrong type, reserved byte, or payload length
        let end = data.len() - 8;
        let hash = storage::checksum(&data[..end]).to_le_bytes();
        data[end..].copy_from_slice(&hash);
        fs::write(&manifest, &data).unwrap();
        assert_eq!(
            Vfs::open_disk(&dir.0, DiskOptions::default()).err(),
            Some(Errno(22))
        );
        assert!(orphan.exists());
        assert_eq!(fs::read(&manifest).unwrap(), data);
    }
}
#[test]
fn fifo_inode_persists_but_live_channel_does_not() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.mknod_at(AT_FDCWD, b"/fifo", 0o10640, 0).unwrap();
    v.link_at(AT_FDCWD, b"/fifo", AT_FDCWD, b"/fifo-alias")
        .unwrap();
    let fd = v.open_at(AT_FDCWD, b"/fifo", 2 | O_NONBLOCK, 0).unwrap();
    v.write(fd, b"unpersisted").unwrap();
    let stat = v.stat_fd(fd).unwrap();
    v.sync().unwrap();
    drop(v);
    let mut v = dir.open();
    let reopened = v.stat_at(AT_FDCWD, b"/fifo").unwrap();
    assert_eq!(&stat[..32], &reopened[..32]);
    assert_eq!(v.stat_at(AT_FDCWD, b"/fifo-alias").unwrap(), reopened);
    let fd = v.open_at(AT_FDCWD, b"/fifo", 2 | O_NONBLOCK, 0).unwrap();
    assert_eq!(v.read(fd, 32), Err(Errno(11)));
    let writer = v
        .open_at(AT_FDCWD, b"/fifo-alias", 1 | O_NONBLOCK, 0)
        .unwrap();
    v.write(writer, b"live").unwrap();
    assert_eq!(v.read(fd, 32).unwrap(), b"live");
}
#[test]
#[cfg(target_os = "linux")]
fn closed_inodes_do_not_retain_native_file_descriptors() {
    let dir = Temp::new();
    let mut v = dir.open();
    for n in 0..600 {
        v.import_file(format!("/usr/test/{n}").as_bytes(), b"retained".to_vec())
            .unwrap();
    }
    v.sync().unwrap();
    drop(v);
    let mut v = dir.open();
    let fd = v.open_at(AT_FDCWD, b"/usr/test/599", 2, 0).unwrap();
    v.unlink_at(AT_FDCWD, b"/usr/test/599", false).unwrap();
    assert_eq!(v.read(fd, 8).unwrap(), b"retained");
    v.pwrite(fd, b"X", 0).unwrap();
    v.sync_fd(fd, false).unwrap();
    for entry in fs::read_dir("/proc/self/fd").unwrap() {
        if let Ok(path) = fs::read_link(entry.unwrap().path()) {
            assert!(
                !path.starts_with(dir.0.join("objects")),
                "retained host descriptor: {path:?}"
            );
        }
    }
    v.close(fd).unwrap();
}
#[test]
fn recorded_limits_and_writable_usr_survive_reopen() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.set_storage_limits(StorageLimits {
        file_bytes: 1234567,
        nodes: 16_384,
    })
    .unwrap();
    v.import_file(b"/usr/local/test", b"writable".to_vec())
        .unwrap();
    drop(v);
    let mut v = dir.open();
    assert_eq!(v.capacity().node_limit, 16_384);
    assert_eq!(v.capacity().budget_bytes, 1234567);
    let fd = v.open_at(AT_FDCWD, b"/usr/local/test", 2, 0).unwrap();
    v.write(fd, b"changed").unwrap();
    v.close(fd).unwrap();
    v.set_storage_limits(StorageLimits {
        file_bytes: 1234567,
        nodes: 1000,
    })
    .unwrap();
    drop(v);
    let v = dir.open();
    assert_eq!(v.capacity().node_limit, 1000);
    assert_eq!(v.capacity().budget_bytes, 1234567);
}
#[test]
fn bridge_device_is_volatile_nonseekable_and_shared_by_dup() {
    let dir = Temp::new();
    let mut v = dir.open();
    let broker = trames_bridge::Broker::default();
    v.attach_bridge(broker.clone());
    v.set_runtime_info(1, RuntimeInfo::default());
    let fd = v
        .open_at(AT_FDCWD, b"/dev/trames-bridge", 2 | O_NONBLOCK, 0)
        .unwrap();
    assert_eq!(v.read(fd, 1), Err(Errno(11)));
    assert_eq!(v.poll(fd, 5), 4);
    assert_eq!(v.seek(fd, 0, 0), Err(Errno(29)));
    assert_eq!(v.pread(fd, 1, 0), Err(Errno(29)));
    let other = v.dup(fd, 0, false).unwrap();
    v.write(
        fd,
        b"{\"version\":1,\"id\":1,\"method\":\"bridge.info\",\"params\":{}}\n",
    )
    .unwrap();
    assert_eq!(v.poll(other, 5), 5);
    assert!(!v.read(other, 65536).unwrap().is_empty());
    v.close(fd).unwrap();
    v.close(other).unwrap();
    v.sync().unwrap();
    drop(v);
    let v = dir.open();
    assert_eq!(v.stat_at(AT_FDCWD, b"/dev/trames-bridge"), Err(Errno(2)));
}
#[test]
fn pseudo_views_do_not_enter_the_manifest_or_consume_disk_quota() {
    let dir = Temp::new();
    let mut v = dir.open();
    let before = fs::read(dir.0.join("manifest")).unwrap();
    let used = v.capacity().used_bytes;
    v.set_runtime_info(
        1,
        RuntimeInfo {
            processes: vec![ProcessInfo {
                pid: 1,
                tgid: 1,
                command: b"ash".to_vec(),
                ..ProcessInfo::default()
            }],
            ..RuntimeInfo::default()
        },
    );
    let fd = v.open_at(AT_FDCWD, b"/proc/self/status", 0, 0).unwrap();
    assert!(!v.read(fd, 1024).unwrap().is_empty());
    v.close(fd).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/dev/zero", 0, 0).unwrap();
    assert_eq!(v.read(fd, 4096).unwrap(), vec![0; 4096]);
    v.close(fd).unwrap();
    v.sync().unwrap();
    assert_eq!(fs::read(dir.0.join("manifest")).unwrap(), before);
    assert_eq!(v.capacity().used_bytes, used);
    drop(v);
    let v = dir.open();
    assert_eq!(v.stat_at(AT_FDCWD, b"/proc/1/status"), Err(Errno(2)));
}
#[test]
fn setgid_inheritance_and_setid_bits_follow_guest_ownership() {
    let mut v = Vfs::default();
    v.mkdir_at(AT_FDCWD, b"/shared", 0o777).unwrap();
    v.chown_at(AT_FDCWD, b"/shared", 1000, 3000, false).unwrap();
    v.chmod_at(AT_FDCWD, b"/shared", 0o2777).unwrap();
    v.credentials = Credentials::user(1000, 1000);
    v.credentials.groups.push(3000);
    let fd = v.open_at(AT_FDCWD, b"/shared/data", 0x42, 0o6770).unwrap();
    assert_eq!(&v.stat_fd(fd).unwrap()[28..32], &3000u32.to_le_bytes());
    v.write(fd, b"changed").unwrap();
    assert_eq!(
        u32::from_le_bytes(v.stat_fd(fd).unwrap()[16..20].try_into().unwrap()) & 0o6000,
        0
    );
    v.mkdir_at(AT_FDCWD, b"/shared/sub", 0o755).unwrap();
    let stat = v.stat_at(AT_FDCWD, b"/shared/sub").unwrap();
    assert_eq!(&stat[28..32], &3000u32.to_le_bytes());
    assert_ne!(
        u32::from_le_bytes(stat[16..20].try_into().unwrap()) & 0o2000,
        0
    );
}

#[test]
fn ownership_sticky_modes_and_symlink_ownership_survive_reopening() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.mkdir_at(AT_FDCWD, b"/shared", 0o755).unwrap();
    v.chmod_at(AT_FDCWD, b"/shared", 0o1777).unwrap();
    v.import_file(b"/shared/data", b"durable".to_vec()).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/shared/data", 2, 0).unwrap();
    v.chown_fd(fd, 2000, 4000).unwrap();
    v.chmod_fd(fd, 0o640).unwrap();
    v.symlink_at(b"data", AT_FDCWD, b"/shared/link").unwrap();
    v.chown_at(AT_FDCWD, b"/shared/link", 1234, 4321, true)
        .unwrap();
    v.sync().unwrap();
    drop(v);
    let mut v = dir.open();
    let stat = v.stat_at(AT_FDCWD, b"/shared/data").unwrap();
    assert_eq!(u32::from_le_bytes(stat[24..28].try_into().unwrap()), 2000);
    assert_eq!(u32::from_le_bytes(stat[28..32].try_into().unwrap()), 4000);
    let link = v.stat_at_flags(AT_FDCWD, b"/shared/link", true).unwrap();
    assert_eq!(u32::from_le_bytes(link[24..28].try_into().unwrap()), 1234);
    let mode = v.stat_at(AT_FDCWD, b"/shared").unwrap();
    assert_eq!(
        u32::from_le_bytes(mode[16..20].try_into().unwrap()) & 0o7777,
        0o1777
    );
    v.credentials = Credentials::user(3000, 3000);
    assert_eq!(v.open_at(AT_FDCWD, b"/shared/data", 0, 0), Err(Errno(13)));
    v.credentials.groups.push(4000);
    let fd = v.open_at(AT_FDCWD, b"/shared/data", 0, 0).unwrap();
    assert_eq!(v.read(fd, 32).unwrap(), b"durable");
    assert_eq!(v.open_at(AT_FDCWD, b"/shared/data", 1, 0), Err(Errno(13)));
    assert_eq!(v.unlink_at(AT_FDCWD, b"/shared/data", false), Err(Errno(1)));
    assert_eq!(
        v.chown_at(AT_FDCWD, b"/shared/data", 3000, 3000, false),
        Err(Errno(1))
    );
    assert_eq!(v.credentials.set_id(false, 0), Err(Errno(1)));
    v.credentials = Credentials::user(2000, 4000);
    v.unlink_at(AT_FDCWD, b"/shared/data", false).unwrap();
}

#[test]
fn reopen_restores_byte_paths_hard_links_modes_times_and_bytes() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_file(b"/data/\xff", b"a\0b".to_vec()).unwrap();
    v.link_at(AT_FDCWD, b"/data/\xff", AT_FDCWD, b"/alias")
        .unwrap();
    v.chmod_at(AT_FDCWD, b"/alias", 0o640).unwrap();
    v.set_times(AT_FDCWD, Some(b"/alias"), Some([[123, 456], [789, 321]]))
        .unwrap();
    let stat = v.stat_at(AT_FDCWD, b"/alias").unwrap();
    v.sync().unwrap();
    drop(v);
    let mut v = dir.open();
    assert_eq!(v.stat_at(AT_FDCWD, b"/data/\xff").unwrap(), stat);
    assert_eq!(v.allocated_bytes(), 3);
    let fd = v.open_at(AT_FDCWD, b"/alias", 2, 0).unwrap();
    assert_eq!(v.read(fd, 3).unwrap(), b"a\0b");
    v.pwrite(fd, b"Z", 1).unwrap();
    let other = v.open_at(AT_FDCWD, b"/data/\xff", 0, 0).unwrap();
    assert_eq!(v.read(other, 3).unwrap(), b"aZb");
}
#[test]
fn sparse_16_gib_file_exhausts_logical_quota_without_a_large_buffer() {
    let dir = Temp::new();
    let mut v = dir.open();
    let fd = v.open_at(AT_FDCWD, b"/large", 0x42, 0o600).unwrap();
    v.truncate_fd(fd, DEFAULT_DISK_BYTES).unwrap();
    v.pwrite(fd, b"X", DEFAULT_DISK_BYTES - 1).unwrap();
    assert_eq!(v.allocated_bytes(), DEFAULT_DISK_BYTES);
    assert_eq!(v.pread(fd, 1, DEFAULT_DISK_BYTES - 1).unwrap(), b"X");
    assert_eq!(v.pread(fd, 8, DEFAULT_DISK_BYTES - 9).unwrap(), [0; 8]);
    assert_eq!(v.pwrite(fd, b"Y", DEFAULT_DISK_BYTES), Err(Errno(28)));
    assert_eq!(v.truncate_fd(fd, DEFAULT_DISK_BYTES + 1), Err(Errno(28)));
    assert_eq!(size(v.stat_fd(fd).unwrap()), DEFAULT_DISK_BYTES);
    let stat = v.stat_fd(fd).unwrap();
    assert!(u64::from_le_bytes(stat[64..72].try_into().unwrap()) * 512 < 1024 * 1024);
    assert_eq!(v.seek(fd, 0, 1).unwrap(), 0);
    v.sync().unwrap();
    drop(v);
    let v = dir.open();
    assert_eq!(
        size(v.stat_at(AT_FDCWD, b"/large").unwrap()),
        DEFAULT_DISK_BYTES
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let object = fs::read_dir(dir.0.join("objects"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert!(object.metadata().unwrap().blocks() * 512 < 1024 * 1024);
    }
}
#[test]
fn disk_fork_and_unlink_keep_shared_offsets_and_account_open_files() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.set_storage_limits(StorageLimits {
        file_bytes: 4,
        nodes: 20,
    })
    .unwrap();
    v.import_file(b"/a", b"abcd".to_vec()).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/a", 2, 0).unwrap();
    let mut child = v.clone();
    assert_eq!(child.read(fd, 1).unwrap(), b"a");
    assert_eq!(v.read(fd, 1).unwrap(), b"b");
    v.unlink_at(AT_FDCWD, b"/a", false).unwrap();
    assert_eq!(v.allocated_bytes(), 4);
    assert_eq!(v.import_file(b"/b", vec![1]), Err(Errno(28)));
    v.close(fd).unwrap();
    assert_eq!(child.read(fd, 2).unwrap(), b"cd");
    child.close(fd).unwrap();
    assert_eq!(v.allocated_bytes(), 0);
    v.import_file(b"/b", vec![1]).unwrap();
    drop(child);
    drop(v);
    let v = dir.open();
    assert_eq!(v.capacity().budget_bytes, 4);
    assert_eq!(v.allocated_bytes(), 1);
    assert_eq!(fs::read_dir(dir.0.join("objects")).unwrap().count(), 1);
}
#[test]
fn disk_store_lock_lasts_until_the_last_process_clone_is_dropped() {
    let dir = Temp::new();
    let v = dir.open();
    let child = v.clone();
    drop(v);
    assert_eq!(
        Vfs::open_disk(&dir.0, DiskOptions::default()).err(),
        Some(Errno(16))
    );
    drop(child);
    let _v = dir.open();
}
#[test]
fn app_private_owner_lock_retains_exclusivity_without_locking_shared_store() {
    let dir = Temp::new();
    let private = Temp::new();
    let lock = private.0.join("environment-owner.lock");
    let v = Vfs::open_disk_with_owner_lock(&dir.0, DiskOptions::default(), &lock).unwrap();
    let child = v.clone();
    drop(v);
    assert!(!dir.0.join(".lock").exists());
    assert_eq!(
        Vfs::open_disk_with_owner_lock(&dir.0, DiskOptions::default(), &lock).err(),
        Some(Errno(16))
    );
    assert_eq!(
        Vfs::reset_disk_with_owner_lock(&dir.0, &lock),
        Err(Errno(16))
    );
    drop(child);
    let mut v = Vfs::open_disk_with_owner_lock(&dir.0, DiskOptions::default(), &lock).unwrap();
    v.import_file(b"/retained", b"data".to_vec()).unwrap();
    drop(v);
    let v = Vfs::open_disk_with_owner_lock(&dir.0, DiskOptions::default(), &lock).unwrap();
    assert!(v.stat_at(AT_FDCWD, b"/retained").is_ok());
    drop(v);
    Vfs::reset_disk_with_owner_lock(&dir.0, &lock).unwrap();
}
#[test]
fn volume_snapshots_bound_growth_and_refresh_independently_of_budget() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.set_volume_space(VolumeSpace {
        total_bytes: 1000,
        available_bytes: 10,
    })
    .unwrap();
    v.import_file(b"/a", vec![1; 8]).unwrap();
    assert_eq!(v.capacity().available_bytes, 2);
    assert_eq!(v.capacity().budget_bytes, 1000);
    assert_eq!(v.import_file(b"/b", vec![1; 3]), Err(Errno(28)));
    v.set_volume_space(VolumeSpace {
        total_bytes: 1000,
        available_bytes: 20,
    })
    .unwrap();
    v.import_file(b"/b", vec![1; 3]).unwrap();
    assert_eq!(v.capacity().available_bytes, 17);
    v.unlink_at(AT_FDCWD, b"/a", false).unwrap();
    assert_eq!(v.capacity().available_bytes, 25);
    assert_eq!(
        v.set_volume_space(VolumeSpace {
            total_bytes: 1,
            available_bytes: 2
        }),
        Err(Errno(22))
    );
    assert_eq!(
        v.set_storage_limits(StorageLimits {
            file_bytes: 2,
            nodes: 20
        }),
        Err(Errno(28))
    );
}
#[test]
fn failed_namespace_commit_rolls_back_create_alias_rename_chmod_and_unlink() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_file(b"/a", b"original".to_vec()).unwrap();
    let before = v.stat_at(AT_FDCWD, b"/a").unwrap();
    fs::create_dir(dir.0.join("manifest.new")).unwrap();
    assert!(v.open_at(AT_FDCWD, b"/b", 0x42, 0o600).is_err());
    assert!(v.link_at(AT_FDCWD, b"/a", AT_FDCWD, b"/alias").is_err());
    assert!(v.rename_at(AT_FDCWD, b"/a", AT_FDCWD, b"/new", 0).is_err());
    assert!(v.chmod_at(AT_FDCWD, b"/a", 0o000).is_err());
    assert!(v.unlink_at(AT_FDCWD, b"/a", false).is_err());
    assert_eq!(v.stat_at(AT_FDCWD, b"/a").unwrap(), before);
    for path in [b"/b".as_slice(), b"/alias", b"/new"] {
        assert_eq!(v.stat_at(AT_FDCWD, path), Err(Errno(2)));
    }
    assert_eq!(fs::read_dir(dir.0.join("objects")).unwrap().count(), 1);
    fs::remove_dir(dir.0.join("manifest.new")).unwrap();
    drop(v);
    let _v = dir.open();
}
#[test]
fn recover_removes_only_validated_orphan_objects_and_abandoned_manifest() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_file(b"/keep", vec![9]).unwrap();
    v.sync().unwrap();
    drop(v);
    let garbage = dir.0.join("objects/ffffffffffffffff.dat");
    fs::write(&garbage, b"orphan").unwrap();
    fs::write(dir.0.join("manifest.new"), b"interrupted").unwrap();
    let v = dir.open();
    assert!(!garbage.exists());
    assert!(!dir.0.join("manifest.new").exists());
    assert_eq!(v.allocated_bytes(), 1);
}
#[test]
fn corrupt_manifest_is_rejected_without_deleting_objects() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_file(b"/keep", vec![9]).unwrap();
    drop(v);
    let garbage = dir.0.join("objects/ffffffffffffffff.dat");
    fs::write(&garbage, b"orphan").unwrap();
    let path = dir.0.join("manifest");
    let mut bytes = fs::read(&path).unwrap();
    bytes[20] ^= 1;
    fs::write(path, bytes).unwrap();
    assert_eq!(
        Vfs::open_disk(&dir.0, DiskOptions::default()).err(),
        Some(Errno(22))
    );
    assert!(garbage.exists());
    assert_eq!(fs::read_dir(dir.0.join("objects")).unwrap().count(), 2);
}
#[test]
fn stream_import_export_uses_bounded_chunks_and_rejects_over_budget() {
    struct Source {
        left: usize,
    }
    impl std::io::Read for Source {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            assert!(buffer.len() <= 65536);
            let n = buffer.len().min(self.left);
            buffer[..n].fill(0x5a);
            self.left -= n;
            Ok(n)
        }
    }
    struct Sink {
        bytes: u64,
    }
    impl std::io::Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            assert!(bytes.len() <= 65536);
            assert!(bytes.iter().all(|&b| b == 0x5a));
            self.bytes += bytes.len() as u64;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let dir = Temp::new();
    let mut v = dir.open();
    let length = 20 * 1024 * 1024 + 7;
    assert_eq!(
        v.import_reader(b"/big", &mut Source { left: length }, false)
            .unwrap(),
        length as u64
    );
    let mut sink = Sink { bytes: 0 };
    assert_eq!(v.export_writer(b"/big", &mut sink).unwrap(), length as u64);
    assert_eq!(sink.bytes, length as u64);
    let before = v.allocated_bytes();
    v.set_storage_limits(StorageLimits {
        file_bytes: before + 2,
        nodes: 100,
    })
    .unwrap();
    assert_eq!(
        v.import_reader(b"/too-big", &mut Source { left: 3 }, false),
        Err(Errno(28))
    );
    assert_eq!(v.allocated_bytes(), before);
    assert_eq!(v.stat_at(AT_FDCWD, b"/too-big"), Err(Errno(2)));
}
#[test]
fn subtree_rename_updates_other_process_cwd_and_open_dirfd() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_file(b"/old/sub/file", vec![1]).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/old/sub", O_DIRECTORY, 0).unwrap();
    let mut child = v.clone();
    child.chdir(b"/old/sub").unwrap();
    v.rename_at(AT_FDCWD, b"/old", AT_FDCWD, b"/new", 0)
        .unwrap();
    assert_eq!(child.cwd().unwrap(), b"/new/sub");
    assert_eq!(child.resolve(fd as i32, b"file").unwrap(), b"/new/sub/file");
    assert_eq!(child.getdents(fd, 4096).unwrap().len(), 72);
    assert_eq!(
        v.rename_at(AT_FDCWD, b"/new", AT_FDCWD, b"/new/sub/nested", 0),
        Err(Errno(22))
    );
    drop(child);
    drop(v);
    let v = dir.open();
    assert!(v.stat_at(AT_FDCWD, b"/new/sub/file").is_ok());
}
#[test]
fn replacing_executable_updates_aliases_but_open_descriptions_keep_old_data() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.install_executable(b"/bin/program", b"old").unwrap();
    v.import_alias(b"/bin/program", b"/alias", true).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/alias", 0, 0).unwrap();
    v.install_executable(b"/bin/program", b"replacement")
        .unwrap();
    assert_eq!(v.read(fd, 20).unwrap(), b"old");
    assert_eq!(v.executable(b"/alias").unwrap(), b"replacement");
    assert_eq!(v.allocated_bytes(), 14);
    v.close(fd).unwrap();
    assert_eq!(v.allocated_bytes(), 11);
    drop(v);
    let v = dir.open();
    assert_eq!(v.executable(b"/alias").unwrap(), b"replacement");
}
#[cfg(unix)]
#[test]
fn symlinked_private_objects_and_dangling_lock_are_rejected() {
    use std::os::unix::fs::symlink;
    let dir = Temp::new();
    let outside = Temp::new();
    let target = outside.0.join("untouched");
    fs::write(&target, b"safe").unwrap();
    let mut v = dir.open();
    v.import_file(b"/keep", vec![9]).unwrap();
    drop(v);
    let object = fs::read_dir(dir.0.join("objects"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::remove_file(&object).unwrap();
    symlink(&target, &object).unwrap();
    assert_eq!(
        Vfs::open_disk(&dir.0, DiskOptions::default()).err(),
        Some(Errno(22))
    );
    assert_eq!(fs::read(target).unwrap(), b"safe");
    let dir = Temp::new();
    let target = outside.0.join("never-created");
    symlink(&target, dir.0.join(".lock")).unwrap();
    assert_eq!(
        Vfs::open_disk(&dir.0, DiskOptions::default()).err(),
        Some(Errno(22))
    );
    assert!(!target.exists());
}

#[test]
fn symlinks_persist_resolve_relative_and_do_not_follow_on_unlink() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_file(b"/data/file", b"payload".to_vec()).unwrap();
    v.symlink_at(b"../data/file", AT_FDCWD, b"/dev/alias")
        .unwrap();
    v.symlink_at(b"/dev/alias", AT_FDCWD, b"/other").unwrap();
    assert_eq!(v.resolve(AT_FDCWD, b"/other").unwrap(), b"/data/file");
    assert_eq!(
        v.open_at(AT_FDCWD, b"/other", O_NOFOLLOW, 0),
        Err(Errno(40))
    );
    assert_eq!(
        size(v.stat_at_flags(AT_FDCWD, b"/other", true).unwrap()),
        10
    );
    v.sync().unwrap();
    drop(v);
    let mut v = dir.open();
    assert_eq!(
        v.readlink_at(AT_FDCWD, b"/dev/alias").unwrap(),
        b"../data/file"
    );
    v.unlink_at(AT_FDCWD, b"/other", false).unwrap();
    assert!(v.stat_at(AT_FDCWD, b"/data/file").is_ok());
    v.symlink_at(b"loop", AT_FDCWD, b"/loop").unwrap();
    assert_eq!(v.resolve(AT_FDCWD, b"/loop"), Err(Errno(40)));
    v.symlink_at(b"/../../data", AT_FDCWD, b"/dir").unwrap();
    assert_eq!(v.resolve(AT_FDCWD, b"/dir/file").unwrap(), b"/data/file");
}
#[test]
fn flock_is_shared_by_dup_fork_and_released_by_last_close() {
    let mut v = Vfs::default();
    v.import_file(b"/lock", vec![]).unwrap();
    let a = v.open_at(AT_FDCWD, b"/lock", 2, 0).unwrap();
    let b = v.open_at(AT_FDCWD, b"/lock", 2, 0).unwrap();
    v.flock(a, 2 | 4).unwrap();
    assert_eq!(v.flock(b, 1 | 4), Err(Errno(11)));
    let mut child = v.clone();
    let alias = child.dup(a, 0, false).unwrap();
    v.close(a).unwrap();
    child.close(a).unwrap();
    assert_eq!(v.flock(b, 2 | 4), Err(Errno(11)));
    child.close(alias).unwrap();
    v.flock(b, 1 | 4).unwrap();
    let c = v.open_at(AT_FDCWD, b"/lock", 2, 0).unwrap();
    v.flock(c, 1 | 4).unwrap();
    assert_eq!(v.flock(c, 2 | 4), Err(Errno(11)));
    v.flock(b, 8).unwrap();
    v.flock(c, 2 | 4).unwrap();
}

#[test]
fn unsupported_manifest_versions_are_rejected_without_deleting_data() {
    for version in [1u32, 2, 5] {
        let dir = Temp::new();
        let mut v = dir.open();
        v.import_file(b"/data", b"retained".to_vec()).unwrap();
        drop(v);
        let mut data = fs::read(dir.0.join("manifest")).unwrap();
        data[8..12].copy_from_slice(&version.to_le_bytes());
        let end = data.len() - 8;
        let hash = storage::checksum(&data[..end]).to_le_bytes();
        data[end..].copy_from_slice(&hash);
        fs::write(dir.0.join("manifest"), &data).unwrap();
        assert!(matches!(
            Vfs::open_disk(&dir.0, DiskOptions::default()),
            Err(Errno(22))
        ));
        assert_eq!(fs::read(dir.0.join("manifest")).unwrap(), data);
        assert_eq!(fs::read_dir(dir.0.join("objects")).unwrap().count(), 1);
    }
}
#[test]
fn version_three_manifest_reopens_without_attributes_and_upgrades_on_write() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_file(b"/data", b"retained".to_vec()).unwrap();
    drop(v);
    let mut bytes = fs::read(dir.0.join("manifest")).unwrap();
    let count = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
    let mut at = 40;
    for _ in 0..count {
        let size = u32::from_le_bytes(bytes[at + 72..at + 76].try_into().unwrap()) as usize;
        at += 76 + size;
    }
    assert_eq!(&bytes[at..at + 4], &[0; 4]);
    bytes.drain(at..at + 4); // v3 has no attribute table
    bytes[8..12].copy_from_slice(&3u32.to_le_bytes());
    let end = bytes.len() - 8;
    let hash = storage::checksum(&bytes[..end]).to_le_bytes();
    bytes[end..].copy_from_slice(&hash);
    fs::write(dir.0.join("manifest"), bytes).unwrap();
    let mut v = dir.open();
    assert!(v
        .list_xattrs(AT_FDCWD, Some(b"/data"), true)
        .unwrap()
        .is_empty());
    v.set_xattr(
        AT_FDCWD,
        Some(b"/data"),
        true,
        b"user.upgrade",
        Some(b"yes"),
        0,
    )
    .unwrap();
    drop(v);
    let bytes = fs::read(dir.0.join("manifest")).unwrap();
    assert_eq!(&bytes[8..12], &4u32.to_le_bytes());
    assert_eq!(
        dir.open()
            .get_xattr(AT_FDCWD, Some(b"/data"), true, b"user.upgrade")
            .unwrap(),
        b"yes"
    );
}
#[test]
fn explicit_reset_refuses_live_stores_and_clears_unsupported_metadata() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.import_file(b"/data", b"data".to_vec()).unwrap();
    assert_eq!(Vfs::reset_disk(&dir.0), Err(Errno(16)));
    assert!(dir.0.join("manifest").exists());
    drop(v);
    fs::write(dir.0.join("manifest"), b"unsupported old format").unwrap();
    Vfs::reset_disk(&dir.0).unwrap();
    assert!(!dir.0.exists());
    let v = dir.open();
    assert_eq!(v.stat_at(AT_FDCWD, b"/data"), Err(Errno(2)));
}

#[test]
fn direct_native_mapped_writes_survive_disk_sync_unmap_and_reopen() {
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    let dir = Temp::new();
    let mut v = dir.open();
    let fd = v.open_at(AT_FDCWD, b"/native-disk", 0x42, 0o600).unwrap();
    v.truncate_fd(fd, PAGE_SIZE * 2).unwrap();
    let objects = v.mapping_pages(fd, 0, PAGE_SIZE * 2, true, true).unwrap();
    let mut m = Memory::default();
    m.map_backed(0x1000, objects, true, Permissions::RW, false)
        .unwrap();
    assert!(m.native_output_range(0x1ffe, 8).unwrap());
    assert!(!m.native_writable_range(0x1ffe, 8).unwrap());
    assert_eq!(
        m.fill_with(0x1ffe, 8, |bytes| bytes.fill(91))
            .unwrap()
            .direct_write,
        8
    );
    m.sync_range(0x1000, PAGE_SIZE * 2).unwrap();
    m.unmap(0x1000, PAGE_SIZE * 2).unwrap();
    v.close(fd).unwrap();
    drop(m);
    drop(v);
    let mut v = dir.open();
    let fd = v.open_at(AT_FDCWD, b"/native-disk", 0, 0).unwrap();
    v.seek(fd, 4094, 0).unwrap();
    assert_eq!(v.read(fd, 8).unwrap(), vec![91; 8]);
}

#[test]
fn named_socket_inodes_reopen_as_stale_endpoints() {
    let dir = Temp::new();
    let mut v = dir.open();
    let fd = v.socket(1, 1, 0).unwrap();
    let socket = v.local_socket(fd).unwrap().unwrap();
    v.local_bind(&socket, b"\x01\x00/socket\0").unwrap();
    socket.listen(1).unwrap();
    v.link_at(AT_FDCWD, b"/socket", AT_FDCWD, b"/alias")
        .unwrap();
    v.sync().unwrap();
    drop(socket);
    drop(v);
    let mut v = dir.open();
    let stat = v.stat_at(AT_FDCWD, b"/alias").unwrap();
    assert_eq!(
        u32::from_le_bytes(stat[16..20].try_into().unwrap()) & 0o170000,
        0o140000
    );
    let fd = v.socket(1, 1, 0).unwrap();
    let socket = v.local_socket(fd).unwrap().unwrap();
    assert_eq!(
        v.local_connect(&socket, b"\x01\x00/alias\0"),
        Err(Errno(111))
    );
    assert_eq!(v.local_bind(&socket, b"\x01\x00/alias\0"), Err(Errno(98)));
    v.unlink_at(AT_FDCWD, b"/alias", false).unwrap();
    v.local_bind(&socket, b"\x01\x00/alias\0").unwrap();
    assert_eq!(
        v.local_connect(&socket, b"\x01\x00/socket\0"),
        Err(Errno(111))
    );
}

#[test]
fn reopened_inode_watches_keep_parent_identity_and_failed_transactions_are_silent() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.mkdir_at(AT_FDCWD, b"/watched", 0o700).unwrap();
    v.import_file(b"/watched/file", b"data".to_vec()).unwrap();
    drop(v);
    let mut v = dir.open();
    let fd = v.inotify_init(O_NONBLOCK).unwrap();
    let wd = v
        .inotify_add(fd, b"/watched", inotify::ACCESS | inotify::CREATE)
        .unwrap();
    let file = v.open_at(AT_FDCWD, b"/watched/file", 0, 0).unwrap();
    assert_eq!(v.read(file, 4).unwrap(), b"data");
    let bytes = v.read(fd, 128).unwrap();
    assert_eq!(i32::from_le_bytes(bytes[..4].try_into().unwrap()), wd);
    assert_eq!(
        u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        inotify::ACCESS
    );
    assert_eq!(&bytes[16..21], b"file\0");
    fs::create_dir(dir.0.join("manifest.new")).unwrap();
    assert!(v.mkdir_at(AT_FDCWD, b"/watched/failed", 0o700).is_err());
    assert_eq!(v.read(fd, 128), Err(Errno(11)));
    fs::remove_dir(dir.0.join("manifest.new")).unwrap();
}

#[test]
fn anonymous_inode_metadata_does_not_commit_or_search_the_disk_namespace() {
    let dir = Temp::new();
    let mut v = dir.open();
    let fd = v.memfd_create(b"wayland-frame", 2).unwrap();
    let named = v.open_at(AT_FDCWD, b"/control", 0o102, 0o600).unwrap();
    let before = fs::read(dir.0.join("manifest")).unwrap();
    // Any attempted namespace commit now fails at create_new(manifest.new).
    fs::create_dir(dir.0.join("manifest.new")).unwrap();
    for length in [0, 4096, 16384, 65536, 4096] {
        v.truncate_fd(fd, length).unwrap();
        assert_eq!(size(super::Vfs::stat_fd(&v, fd).unwrap()), length);
    }
    v.chmod_fd(fd, 0o640).unwrap();
    v.chown_fd(fd, 1000, 1000).unwrap();
    v.set_xattr(fd as i32, None, true, b"user.test", Some(b"memory"), 0)
        .unwrap();
    v.sync_fd(fd, false).unwrap();
    v.sync_fd(fd, true).unwrap();
    let _ = v.fd_snapshot(); // Warm the unrelated named control's hint.
    let before_paths = PATH_SEARCHES.with(Cell::get);
    for _ in 0..32 {
        let entry = v
            .fd_snapshot()
            .into_iter()
            .find(|entry| entry.fd == fd)
            .unwrap();
        assert_eq!(entry.target, b"/memfd:wayland-frame (deleted)");
    }
    assert_eq!(
        PATH_SEARCHES.with(Cell::get),
        before_paths,
        "unnamed inodes cannot scan a directory tree"
    );
    assert_eq!(fs::read(dir.0.join("manifest")).unwrap(), before);
    assert!(
        v.truncate_fd(named, 4096).is_err(),
        "named files retain their existing namespace durability path"
    );
}
#[test]
fn deferred_weak_inode_collection_preserves_the_exact_live_quota() {
    let mut v = Vfs::default();
    let limit = v.fs.borrow().inodes.len() + 4;
    v.fs.borrow_mut().limits.nodes = limit;
    for _ in 0..128 {
        let fd = v.memfd_create(b"reused", 0).unwrap();
        v.close(fd).unwrap();
        assert!(v.fs.borrow().inodes.len() <= limit);
    }
    let mut live = Vec::new();
    while let Ok(fd) = v.memfd_create(b"live", 0) {
        live.push(fd);
    }
    assert_eq!(live.len(), 4);
    assert_eq!(v.memfd_create(b"over-limit", 0), Err(Errno(28)));
    v.close(live.pop().unwrap()).unwrap();
    v.memfd_create(b"replacement", 0).unwrap();
}

#[test]
fn tmpfs_resize_commits_only_its_own_namespace() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.mkdir_at(AT_FDCWD, b"/ram", 0o755).unwrap();
    v.mount(None, b"/ram", Some(b"tmpfs"), 0, None).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/ram/buffer", 0o102, 0o600).unwrap();
    let before = fs::read(dir.0.join("manifest")).unwrap();
    fs::create_dir(dir.0.join("manifest.new")).unwrap();
    v.truncate_fd(fd, 65536).unwrap();
    v.sync_fd(fd, false).unwrap();
    v.sync_fd(fd, true).unwrap();
    assert_eq!(size(v.stat_fd(fd).unwrap()), 65536);
    assert_eq!(fs::read(dir.0.join("manifest")).unwrap(), before);
}

#[test]
fn file_sync_retains_its_mount_after_detach_and_preserves_persistent_errors() {
    let dir = Temp::new();
    let mut v = dir.open();
    v.mkdir_at(AT_FDCWD, b"/ram", 0o755).unwrap();
    v.mount(None, b"/ram", Some(b"tmpfs"), 0, None).unwrap();
    let ram = v.open_at(AT_FDCWD, b"/ram/buffer", 0o102, 0o600).unwrap();
    let named = v.open_at(AT_FDCWD, b"/control", 0o102, 0o600).unwrap();
    let deleted = v.open_at(AT_FDCWD, b"/deleted", 0o102, 0o600).unwrap();
    v.unlink_at(AT_FDCWD, b"/deleted", false).unwrap();
    v.umount(b"/ram", 2).unwrap();
    let before = fs::read(dir.0.join("manifest")).unwrap();
    fs::create_dir(dir.0.join("manifest.new")).unwrap();
    for fd in [ram, deleted] {
        v.write(fd, b"retained").unwrap();
        v.sync_fd(fd, false).unwrap();
        v.sync_fd(fd, true).unwrap();
        assert_eq!(v.pread(fd, 8, 0).unwrap(), b"retained");
    }
    assert!(v.sync_fd(named, false).is_err());
    assert!(v.sync_fd(named, true).is_err());
    assert_eq!(fs::read(dir.0.join("manifest")).unwrap(), before);
}
