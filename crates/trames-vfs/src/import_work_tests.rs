// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned streams retain a consumed buffer and unpublished bytes across waits.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

struct Store(std::path::PathBuf);
impl Store {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "trames-import-work-{}-{}",
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
struct Stream {
    data: std::io::Cursor<Vec<u8>>,
    reads: Arc<AtomicUsize>,
}
impl Read for Stream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.reads.fetch_add(1, Relaxed);
        self.data.read(out)
    }
}
fn stream(bytes: Vec<u8>) -> (Stream, Arc<AtomicUsize>) {
    let reads = Arc::new(AtomicUsize::new(0));
    (
        Stream {
            data: std::io::Cursor::new(bytes),
            reads: reads.clone(),
        },
        reads,
    )
}
fn write(v: &mut Vfs, path: &[u8], bytes: &[u8]) {
    let fd = v.open_at(AT_FDCWD, path, 2, 0).unwrap();
    assert_eq!(v.write(fd, bytes).unwrap(), bytes.len());
    v.close(fd).unwrap();
}
fn stat(v: &mut Vfs, field: &str) -> u64 {
    let fd = v
        .open_at(AT_FDCWD, b"/sys/fs/cgroup/a/io.stat", 0, 0)
        .unwrap();
    let bytes = v.pread(fd, 4096, 0).unwrap();
    v.close(fd).unwrap();
    String::from_utf8(bytes)
        .unwrap()
        .split_whitespace()
        .find_map(|word| word.strip_prefix(field).map(|value| value.parse().unwrap()))
        .unwrap_or(0)
}
fn setup(store: &Store) -> Vfs {
    let mut v = Vfs::open_disk(&store.0, Default::default()).unwrap();
    v.set_runtime_info(1, Default::default());
    write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"+io");
    v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/a", 0o755).unwrap();
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=1");
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    v
}
#[test]
fn accepted_import_keeps_consumed_input_and_original_owner_until_one_publication() {
    for replace in [false, true] {
        let store = Store::new();
        let mut v = setup(&store);
        let old = if replace {
            v.import_file(b"/data", b"old".to_vec()).unwrap();
            Some(v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap())
        } else {
            None
        };
        let bytes = [vec![1; 65536], vec![2; 65536], vec![3; 65536]].concat();
        let (reader, reads) = stream(bytes.clone());
        let task = v.cgroup_task(1).unwrap();
        let scope = task.resource_scope();
        let mut request = v.host_import(b"/data", reader, replace, false);
        assert!(request.run().unwrap().is_none());
        assert_eq!(reads.load(Relaxed), 2);
        assert_eq!(stat(&mut v, "wios="), 1);
        assert_eq!(stat(&mut v, "wbytes="), 65536);
        if let Some(fd) = old {
            assert_eq!(v.pread(fd, 3, 0).unwrap(), b"old");
        } else {
            assert!(v.stat_at(AT_FDCWD, b"/data").is_err());
        }
        write(&mut v, b"/sys/fs/cgroup/cgroup.procs", b"1");
        drop(scope);
        assert!(request.run().unwrap().is_none());
        assert_eq!(
            reads.load(Relaxed),
            2,
            "an accepted buffer is not read again while pending"
        );
        write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=max");
        let published = std::thread::spawn(move || request.run().unwrap().unwrap())
            .join()
            .unwrap();
        assert_eq!(published.bytes, bytes.len() as u64);
        assert_eq!(reads.load(Relaxed), 4);
        assert_eq!(stat(&mut v, "wios="), 4);
        assert_eq!(
            stat(&mut v, "wbytes="),
            bytes.len() as u64 + std::fs::metadata(store.0.join("manifest")).unwrap().len()
        );
        let fd = v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
        assert_eq!(v.pread(fd, bytes.len(), 0).unwrap(), bytes);
        let metadata = v.stat_fd(fd).unwrap();
        assert_eq!(
            u64::from_le_bytes(metadata[8..16].try_into().unwrap()),
            published.inode
        );
        if let Some(fd) = old {
            assert_eq!(v.pread(fd, 3, 0).unwrap(), b"old");
        }
    }
}
#[test]
fn a_manifest_wait_keeps_the_finished_import_stage_without_reading_or_writing_it_again() {
    for replace in [false, true] {
        for cancel in [false, true] {
            let store = Store::new();
            let mut v = setup(&store);
            if replace {
                v.import_file(b"/data", b"old".to_vec()).unwrap();
            }
            let baseline = v.capacity().used_bytes;
            let (reader, reads) = stream(vec![7; 65536]);
            let task = v.cgroup_task(1).unwrap();
            let scope = task.resource_scope();
            let mut request = v.host_import(b"/data", reader, replace, false);
            assert!(request.run().unwrap().is_none());
            assert!(request.wait().is_some());
            assert_eq!(reads.load(Relaxed), 2);
            assert_eq!(stat(&mut v, "wios="), 1);
            assert_eq!(v.capacity().used_bytes, baseline + 65536);
            assert!(!store.0.join("manifest.new").exists());
            write(&mut v, b"/sys/fs/cgroup/cgroup.procs", b"1");
            drop(scope);
            if cancel {
                drop(request);
                assert_eq!(v.capacity().used_bytes, baseline);
                assert_eq!(stat(&mut v, "wios="), 1);
                if replace {
                    let fd = v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
                    assert_eq!(v.read(fd, 3).unwrap(), b"old");
                } else {
                    assert!(v.stat_at(AT_FDCWD, b"/data").is_err());
                }
            } else {
                write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=max");
                assert_eq!(request.run().unwrap().unwrap().bytes, 65536);
                assert_eq!(stat(&mut v, "wios="), 2);
                assert_eq!(
                    stat(&mut v, "wbytes="),
                    65536 + std::fs::metadata(store.0.join("manifest")).unwrap().len()
                );
                let fd = v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
                assert_eq!(v.read(fd, 65536).unwrap(), vec![7; 65536]);
            }
            assert_eq!(
                reads.load(Relaxed),
                2,
                "publication does not reconsume the finished stream"
            );
        }
    }
}
#[test]
fn cancelling_a_pending_import_refunds_anonymous_storage_and_keeps_the_old_file() {
    let store = Store::new();
    let mut v = setup(&store);
    v.import_file(b"/data", b"old".to_vec()).unwrap();
    let baseline = v.capacity().used_bytes;
    let (reader, reads) = stream(vec![7; 131072]);
    let task = v.cgroup_task(1).unwrap();
    let _scope = task.resource_scope();
    let mut request = v.host_import(b"/data", reader, true, false);
    assert!(request.run().unwrap().is_none());
    assert_eq!(v.capacity().used_bytes, baseline + 65536);
    assert_eq!(request.run_checked(|| true).unwrap_err(), Errno(4));
    assert_eq!(reads.load(Relaxed), 2);
    drop(request);
    assert_eq!(v.capacity().used_bytes, baseline);
    let fd = v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
    assert_eq!(v.read(fd, 3).unwrap(), b"old");
    assert_eq!(stat(&mut v, "wios="), 1);
}
#[test]
fn invalid_destination_consumes_no_original_stream_bytes() {
    let store = Store::new();
    let mut v = setup(&store);
    v.import_file(b"/data", b"old".to_vec()).unwrap();
    let baseline = v.capacity().used_bytes;
    let (reader, reads) = stream(vec![7; 10]);
    let mut request = v.host_import(b"/data", reader, false, false);
    assert_eq!(request.run().unwrap_err(), Errno(17));
    assert_eq!(reads.load(Relaxed), 0);
    assert_eq!(v.capacity().used_bytes, baseline);
}
#[test]
fn a_pending_stream_read_keeps_its_delivered_prefix_before_private_disk_writes() {
    struct Source {
        phase: usize,
        wait: Arc<trames_memory::PageWait>,
    }
    impl Read for Source {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.phase += 1;
            match self.phase {
                1 => {
                    out[..7].copy_from_slice(b"prefix-");
                    Err(trames_shared::ResourcePending::add_progress(
                        trames_shared::ResourcePending::io_error(self.wait.clone()),
                        7,
                    ))
                }
                2 => {
                    out[..4].copy_from_slice(b"tail");
                    Ok(4)
                }
                3 => Ok(0),
                _ => panic!("an accepted input prefix must not be read twice"),
            }
        }
    }
    let store = Store::new();
    let mut v = Vfs::open_disk(&store.0, Default::default()).unwrap();
    let wait = Arc::new(trames_memory::PageWait::default());
    let mut request = v.host_import(
        b"/data",
        Source {
            phase: 0,
            wait: wait.clone(),
        },
        false,
        false,
    );
    assert!(request.run().unwrap().is_none());
    assert_eq!(v.capacity().used_bytes, 0);
    assert!(request.run().unwrap().is_none());
    wait.finish();
    let result = request.run().unwrap().unwrap();
    assert_eq!(result.bytes, 11);
    let fd = v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
    assert_eq!(v.read(fd, 32).unwrap(), b"prefix-tail");
}
