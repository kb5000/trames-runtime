// SPDX-License-Identifier: GPL-3.0-or-later
//! Actual private-disk requests, retained source ownership and controller files.
use super::*;
use crate::*;
use std::{fs, path::PathBuf};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Store(PathBuf);
impl Store {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "trames-cgroup-io-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Store {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn file(v: &mut Vfs, path: &[u8]) -> u32 {
    v.open_at(AT_FDCWD, path, 2, 0).unwrap()
}
fn write(v: &mut Vfs, path: &[u8], bytes: &[u8]) {
    let fd = file(v, path);
    assert_eq!(v.write(fd, bytes).unwrap(), bytes.len());
    v.close(fd).unwrap();
}
fn text(v: &Vfs, fd: u32) -> String {
    String::from_utf8(v.pread(fd, 4096, 0).unwrap()).unwrap()
}
fn stat(group: &Arc<Group>, key: &str) -> u64 {
    group
        .format_stat()
        .split_whitespace()
        .find_map(|field| field.strip_prefix(key).map(|n| n.parse().unwrap()))
        .unwrap_or(0)
}
#[test]
fn original_disk_io_is_counted_once_and_waits_survive_migration_fd_reuse_and_retirement() {
    struct Wake(Arc<SharedCell<cgroup::Cgroups>>);
    impl trames_shared::IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            // Configuration and controller-retirement callbacks must not hold
            // the hierarchy transaction while notifying existing waiters.
            let _ = self.0.borrow().groups.len();
        }
    }
    for retire in [false, true] {
        let store = Store::new();
        let mut v = Vfs::open_disk(&store.0, DiskOptions::default()).unwrap();
        v.set_runtime_info(1, RuntimeInfo::default());
        v.import_file(b"/data", b"abcdef".to_vec()).unwrap();
        v.import_file(b"/replacement", b"new".to_vec()).unwrap();
        v.mkdir_at(AT_FDCWD, b"/ram", 0o755).unwrap();
        v.mount(None, b"/ram", Some(b"tmpfs"), 0, None).unwrap();
        let ram = v.open_at(AT_FDCWD, b"/ram/file", 0x42, 0o600).unwrap();
        let [reader, writer] = v.pipe(0).unwrap();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/slow", 0o755).unwrap();
        assert!(matches!(
            v.open_at(AT_FDCWD, b"/sys/fs/cgroup/io.max", 0, 0),
            Err(Errno(2))
        ));
        assert!(matches!(
            v.open_at(AT_FDCWD, b"/sys/fs/cgroup/slow/io.max", 0, 0),
            Err(Errno(2))
        ));
        write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"+io");
        let maximum = file(&mut v, b"/sys/fs/cgroup/slow/io.max");
        let stats = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/slow/io.stat", 0, 0)
            .unwrap();
        assert!(text(&v, maximum).is_empty());
        assert!(text(&v, stats).is_empty());
        let root = v.cgroups.borrow().io_at(cgroup::ROOT);
        let task = v.cgroup_task(1).unwrap();
        let _resources = task.resource_scope();
        write(&mut v, b"/sys/fs/cgroup/slow/cgroup.procs", b"1");
        let original = {
            let cg = v.cgroups.borrow();
            cg.io_at(cg.member_group(1))
        };
        let fd = file(&mut v, b"/data");
        assert_eq!(v.pread(fd, 6, 0).unwrap(), b"abcdef");
        assert_eq!(stat(&original, "rbytes="), 6);
        assert_eq!(stat(&original, "rios="), 1);
        assert_eq!(v.pread(fd, 6, 0).unwrap(), b"abcdef");
        assert_eq!(stat(&original, "rios="), 1, "a cache hit is not disk IO");
        assert_eq!(v.pwrite(fd, b"123", 1), Ok(3));
        assert_eq!(stat(&original, "wbytes="), 3);
        assert_eq!(stat(&original, "wios="), 1);
        let before = text(&v, stats);
        v.pwrite(ram, b"shmem", 0).unwrap();
        v.write(writer, b"pipe").unwrap();
        assert_eq!(v.read(reader, 4).unwrap(), b"pipe");
        assert_eq!(
            text(&v, stats),
            before,
            "tmpfs and pipes do not consume a disk budget"
        );

        v.write(maximum, b"253:1 wbps=1").unwrap();
        assert!(text(&v, maximum).contains("wbps=1"));
        let direct = FileEpoch::default().capture(&v, true).get(fd).unwrap();
        assert!(direct
            .write(b"x", Some(4), &mut DiskReadCache::default())
            .is_none());
        let target = v
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        let work = FileWork::from_vfs(
            &v,
            target,
            FileCommand::Write {
                bytes: vec![b'X'; 4096],
                offset: Some(4),
            },
        );
        let FileOutcome::Waiting(work) = work.exclusive().run() else {
            panic!("actual disk IO must await its budget")
        };
        assert!(!work.ready());
        assert_eq!(
            stat(&original, "wbytes="),
            3,
            "a pending operation issued no backend IO"
        );
        let wake: Arc<dyn trames_shared::IoWake> = Arc::new(Wake(v.cgroups.clone()));
        let signal = IoSignal::new(1, Arc::downgrade(&wake));
        let sources = work.wait_sources(&signal).unwrap();
        assert!(!sources.subscriptions.is_empty());
        assert!(sources
            .deadline
            .is_some_and(|deadline| deadline > Instant::now()));
        v.close(fd).unwrap();
        assert_eq!(file(&mut v, b"/replacement"), fd);
        write(&mut v, b"/sys/fs/cgroup/cgroup.procs", b"1");
        assert!(
            !work.ready(),
            "task migration does not reassign an accepted original IO"
        );
        if retire {
            write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"-io");
            assert_eq!(
                v.pread(maximum, 4096, 0),
                Err(Errno(19)),
                "an old control FD is retired"
            );
        } else {
            v.write(maximum, b"253:1 wbps=max").unwrap();
        }
        assert!(signal.ready());
        assert!(work.ready());
        let FileOutcome::Complete(reply) = work.exclusive().run() else {
            panic!("same original disk request must complete")
        };
        assert!(matches!(reply.result, Ok(FileValue::Count(4096))));
        assert_eq!(stat(&original, "wbytes="), if retire { 3 } else { 4099 });
        assert_eq!(stat(&original, "wios="), if retire { 1 } else { 2 });
        assert_eq!(stat(&root, "wbytes="), 4099);
        assert_eq!(
            v.pread(fd, 3, 0).unwrap(),
            b"new",
            "the reused FD was not retargeted"
        );
        let old = file(&mut v, b"/data");
        let bytes = v.pread(old, 4100, 0).unwrap();
        assert_eq!(&bytes[..4], b"a123");
        assert!(bytes[4..].iter().all(|byte| *byte == b'X'));
        drop(sources);
    }
}
