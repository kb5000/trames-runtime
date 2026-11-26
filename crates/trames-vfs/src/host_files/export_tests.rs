// SPDX-License-Identifier: GPL-3.0-or-later
//! Retained export bytes are independent of path reuse and cache residency.
use super::*;
use std::sync::Mutex;

struct Store(std::path::PathBuf);
impl Store {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "trames-export-work-{}-{}",
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
fn read(v: &mut Vfs, path: &[u8]) -> Vec<u8> {
    let fd = v.open_at(AT_FDCWD, path, 0, 0).unwrap();
    let bytes = v.pread(fd, 4096, 0).unwrap();
    v.close(fd).unwrap();
    bytes
}
struct Sink(Arc<Mutex<Vec<u8>>>);
impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn disk_export_keeps_original_inode_progress_and_owner_after_reclaim_and_migration() {
    let store = Store::new();
    let mut v = Vfs::open_disk(&store.0, Default::default()).unwrap();
    v.set_runtime_info(1, Default::default());
    let bytes = [vec![1; 4096], vec![2; 4096], vec![3; 4096]].concat();
    v.import_file(b"/data", bytes.clone()).unwrap();
    write(
        &mut v,
        b"/sys/fs/cgroup/cgroup.subtree_control",
        b"+memory +io",
    );
    v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/a", 0o755).unwrap();
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=1");
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    let task = v.cgroup_task(1).unwrap();
    let scope = task.resource_scope();
    let fd = v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
    let output = Arc::new(Mutex::new(Vec::new()));
    let mut work = v
        .host_export(b"/data")
        .unwrap()
        .into_work(Sink(output.clone()));
    let layout = work.layout();
    let admission = layout.write().try_enter().ok().unwrap();
    assert!(work.run(&admission, || false).unwrap().is_none());
    assert_eq!(*output.lock().unwrap(), bytes[..4096]);
    assert!(work.wait().unwrap().deadline().is_some());
    drop(admission);
    let reader = layout
        .try_read(trames_memory::Memory::default().memory_report())
        .unwrap();
    drop(reader);
    v.close(fd).unwrap();
    v.rename_at(AT_FDCWD, b"/data", AT_FDCWD, b"/accepted", 0)
        .unwrap();
    write(&mut v, b"/sys/fs/cgroup/cgroup.procs", b"1");
    drop(scope);
    v.import_file(b"/data", b"other inode".to_vec()).unwrap();
    assert_eq!(v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap(), fd);
    write(&mut v, b"/sys/fs/cgroup/a/memory.reclaim", b"4096");
    assert_eq!(read(&mut v, b"/sys/fs/cgroup/a/memory.current"), b"0\n");
    let admission = layout.write().try_enter().ok().unwrap();
    assert!(work.run(&admission, || false).unwrap().is_none());
    drop(admission);
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=max");
    std::thread::spawn(move || {
        let admission = work.layout().write().try_enter().ok().unwrap();
        assert_eq!(work.run(&admission, || false).unwrap(), Some(12288));
        drop(work.into_writer());
    })
    .join()
    .unwrap();
    assert_eq!(*output.lock().unwrap(), bytes);
    let stats = String::from_utf8(read(&mut v, b"/sys/fs/cgroup/a/io.stat")).unwrap();
    assert!(stats.split_whitespace().any(|word| word == "rios=3"));
    assert!(stats.split_whitespace().any(|word| word == "rbytes=12288"));
}
#[test]
fn partial_writer_and_flush_waits_keep_the_original_buffer_and_deliver_each_byte_once() {
    struct Pausing {
        bytes: Vec<u8>,
        calls: usize,
        flushes: usize,
        write_wait: Arc<trames_memory::PageWait>,
        flush_wait: Arc<trames_memory::PageWait>,
    }
    impl Write for Pausing {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            if self.calls == 1 {
                self.bytes.extend_from_slice(&bytes[..7]);
                return Err(trames_shared::ResourcePending::add_progress(
                    trames_shared::ResourcePending::io_error(self.write_wait.clone()),
                    7,
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            if self.flushes == 1 {
                Err(trames_shared::ResourcePending::io_error(
                    self.flush_wait.clone(),
                ))
            } else {
                Ok(())
            }
        }
    }
    let mut v = Vfs::default();
    v.import_file(b"/data", b"prefix-tail".to_vec()).unwrap();
    let write_wait = Arc::new(trames_memory::PageWait::default());
    let flush_wait = Arc::new(trames_memory::PageWait::default());
    let writer = Pausing {
        bytes: Vec::new(),
        calls: 0,
        flushes: 0,
        write_wait: write_wait.clone(),
        flush_wait: flush_wait.clone(),
    };
    let mut work = v.host_export(b"/data").unwrap().into_work(writer);
    let layout = work.layout();
    let admission = layout.write().try_enter().ok().unwrap();
    assert!(work.run(&admission, || false).unwrap().is_none());
    drop(admission);
    write(&mut v, b"/data", b"changed!!!!");
    let admission = layout.write().try_enter().ok().unwrap();
    assert!(work.run(&admission, || false).unwrap().is_none());
    assert_eq!(work.writer.calls, 1);
    assert_eq!(work.run(&admission, || true).unwrap_err(), Errno(4));
    write_wait.finish();
    assert!(work.run(&admission, || false).unwrap().is_none());
    assert_eq!(work.writer.bytes, b"prefix-tail");
    assert_eq!(work.writer.calls, 2);
    assert_eq!(work.writer.flushes, 1);
    flush_wait.finish();
    assert_eq!(work.run(&admission, || false).unwrap(), Some(11));
    let writer = work.into_writer();
    assert_eq!(writer.bytes, b"prefix-tail");
    assert_eq!(writer.calls, 2);
    assert_eq!(writer.flushes, 2);
}
