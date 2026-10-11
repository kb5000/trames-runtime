// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
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
fn legacy_stores_preserve_owner_and_data_when_upgrading_on_checkpoint() {
    for version in [1u32, 2] {
        let dir = Temp::new();
        let mut v = dir.open();
        v.import_file(b"/old", b"legacy data".to_vec()).unwrap();
        v.sync().unwrap();
        drop(v);
        let data = fs::read(dir.0.join("manifest")).unwrap();
        let count = u32::from_le_bytes(data[32..36].try_into().unwrap()) as usize;
        let mut legacy = data[..40].to_vec();
        legacy[8..12].copy_from_slice(&version.to_le_bytes());
        let mut offset = 40;
        for _ in 0..count {
            legacy.extend_from_slice(&data[offset..offset + 12]);
            // v1 predates persisted uid/gid and the v2 symlink payload field.
            legacy
                .extend_from_slice(&data[offset + 20..offset + if version == 1 { 72 } else { 76 }]);
            assert_eq!(&data[offset + 72..offset + 76], &[0; 4]);
            offset += 76;
        }
        legacy.extend_from_slice(&data[offset..data.len() - 8]);
        legacy.extend(storage::checksum(&legacy).to_le_bytes());
        fs::write(dir.0.join("manifest"), legacy).unwrap();
        let mut v = dir.open();
        let fd = v.open_at(AT_FDCWD, b"/old", 0, 0).unwrap();
        assert_eq!(v.read(fd, 32).unwrap(), b"legacy data");
        assert_eq!(
            &v.stat_fd(fd).unwrap()[24..32],
            &[1000u32.to_le_bytes(), 1000u32.to_le_bytes()].concat()
        );
        v.checkpoint().unwrap();
        drop(v);
        assert_eq!(
            &fs::read(dir.0.join("manifest")).unwrap()[8..12],
            &3u32.to_le_bytes()
        );
    }
}
