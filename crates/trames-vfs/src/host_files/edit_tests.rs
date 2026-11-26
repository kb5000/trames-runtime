// SPDX-License-Identifier: GPL-3.0-or-later
//! Compare-and-save owns staged bytes, original providers and checksum progress.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

struct Store(std::path::PathBuf);
impl Store {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "trames-edit-work-{}-{}",
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
    let output = v.read(fd, 1 << 20).unwrap();
    v.close(fd).unwrap();
    output
}
fn setup(store: &Store) -> (Vfs, Vec<u8>) {
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
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=1 wiops=1");
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    (v, bytes)
}
struct Stream {
    data: std::io::Cursor<Vec<u8>>,
    calls: Arc<AtomicUsize>,
}
impl Read for Stream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.calls.fetch_add(1, Relaxed);
        self.data.read(out)
    }
}
fn stream(bytes: Vec<u8>) -> (Stream, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (
        Stream {
            data: std::io::Cursor::new(bytes),
            calls: calls.clone(),
        },
        calls,
    )
}
#[test]
fn conditional_save_resumes_staging_then_validation_without_reconsuming_or_rehashing_prefixes() {
    let store = Store::new();
    let (mut v, original) = setup(&store);
    let old = v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
    let plain = match &v.node(b"/data").unwrap().borrow().content {
        Content::File(storage::FileData::Plain(plain)) => plain.clone(),
        _ => unreachable!(),
    };
    let inode = u64::from_le_bytes(v.stat_fd(old).unwrap()[8..16].try_into().unwrap());
    let baseline = v.capacity().used_bytes;
    let replacement = [vec![8; 65536], vec![9; 65536]].concat();
    let (source, calls) = stream(replacement.clone());
    let task = v.cgroup_task(1).unwrap();
    let scope = task.resource_scope();
    let mut work = v
        .host_edit(b"/data")
        .unwrap()
        .into_work::<_, Vec<u8>>(&v, source);
    let layout = work.layout();
    let admission = layout.write().try_enter().ok().unwrap();
    assert!(work
        .run(
            &admission,
            || false,
            |_, _| panic!("staging is still pending")
        )
        .unwrap()
        .is_none());
    drop(admission);
    assert_eq!(calls.load(Relaxed), 2);
    assert_eq!(v.capacity().used_bytes, baseline + 65536);
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=max");
    let admission = layout.write().try_enter().ok().unwrap();
    assert!(work
        .run(
            &admission,
            || false,
            |_, _| panic!("validation is still pending")
        )
        .unwrap()
        .is_none());
    drop(admission);
    assert_eq!(work.read.as_ref().unwrap().writer(), &original[..4096]);
    let attempted_write = resource_io::Scope::enter();
    assert_eq!(plain.write_at(0, b"late"), Err(Errno(11)));
    let writer_wait = attempted_write.finish().unwrap().wait;
    assert!(
        !writer_wait.ready(),
        "only the original object's writer is waiting"
    );
    assert_eq!(
        plain.read_at(0, 4, None).unwrap(),
        [1; 4],
        "ordinary readers can proceed"
    );
    assert_eq!(calls.load(Relaxed), 3);
    assert_eq!(v.capacity().used_bytes, baseline + replacement.len() as u64);
    write(&mut v, b"/sys/fs/cgroup/cgroup.procs", b"1");
    drop(scope);
    write(&mut v, b"/sys/fs/cgroup/a/memory.reclaim", b"4096");
    assert_eq!(read(&mut v, b"/sys/fs/cgroup/a/memory.current"), b"0\n");
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=max");
    let published = std::thread::spawn(move || {
        let admission = work.layout().write().try_enter().ok().unwrap();
        work.run(
            &admission,
            || false,
            |found, bytes| {
                assert_eq!(found, inode);
                assert_eq!(bytes, &original);
                Ok(false)
            },
        )
        .unwrap()
        .unwrap()
    })
    .join()
    .unwrap();
    assert_ne!(published, inode);
    assert!(
        writer_wait.ready(),
        "successful publication releases the original transaction"
    );
    assert_eq!(calls.load(Relaxed), 3);
    assert_eq!(read(&mut v, b"/data"), replacement);
    assert_eq!(
        v.pread(old, 12288, 0).unwrap(),
        [vec![1; 4096], vec![2; 4096], vec![3; 4096]].concat()
    );
    let stats = String::from_utf8(read(&mut v, b"/sys/fs/cgroup/a/io.stat")).unwrap();
    assert!(stats.split_whitespace().any(|word| word == "rios=3"));
    assert!(stats.split_whitespace().any(|word| word == "wios=3"));
    let written = 131072 + std::fs::metadata(store.0.join("manifest")).unwrap().len();
    assert!(stats
        .split_whitespace()
        .any(|word| word == format!("wbytes={written}")));
}
#[test]
fn path_replacement_and_cancellation_keep_the_old_file_and_refund_the_staged_copy() {
    for cancelled in [false, true] {
        let store = Store::new();
        let (mut v, original) = setup(&store);
        write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=max");
        let task = v.cgroup_task(1).unwrap();
        let scope = task.resource_scope();
        let mut work = v
            .host_edit(b"/data")
            .unwrap()
            .into_work::<_, Vec<u8>>(&v, &b"edited"[..]);
        let layout = work.layout();
        let admission = layout.write().try_enter().ok().unwrap();
        assert!(work
            .run(&admission, || false, |_, _| unreachable!())
            .unwrap()
            .is_none());
        drop(admission);
        write(&mut v, b"/sys/fs/cgroup/cgroup.procs", b"1");
        drop(scope);
        if !cancelled {
            v.rename_at(AT_FDCWD, b"/data", AT_FDCWD, b"/old", 0)
                .unwrap();
            v.import_file(b"/data", b"competing file".to_vec()).unwrap();
            write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=max");
        }
        let before = v.capacity().used_bytes;
        let admission = layout.write().try_enter().ok().unwrap();
        assert_eq!(
            work.run(
                &admission,
                || cancelled,
                |_, bytes| {
                    assert_eq!(bytes, &original);
                    Ok(false)
                }
            )
            .unwrap_err(),
            Errno(if cancelled { 4 } else { 116 })
        );
        drop(admission);
        drop(work);
        assert_eq!(v.capacity().used_bytes, before - 6);
        assert_eq!(
            read(&mut v, b"/data"),
            if cancelled {
                original.clone()
            } else {
                b"competing file".to_vec()
            }
        );
        if !cancelled {
            assert_eq!(read(&mut v, b"/old"), original);
        }
        // Dropping the validation transaction restores the original writer.
        write(&mut v, if cancelled { b"/data" } else { b"/old" }, b"later");
    }
}
#[test]
fn mapped_changes_during_validation_restart_only_the_checksum_and_keep_staged_bytes() {
    let store = Store::new();
    let (mut v, mut original) = setup(&store);
    write(&mut v, b"/sys/fs/cgroup/cgroup.procs", b"1");
    let fd = v.open_at(AT_FDCWD, b"/data", 2, 0).unwrap();
    let maps = v.mapping_pages(fd, 0, 12288, true, true).unwrap();
    let mut first = [0];
    maps[0].read(0, &mut first).unwrap();
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    let task = v.cgroup_task(1).unwrap();
    let _scope = task.resource_scope();
    let (reader, calls) = stream(b"saved".to_vec());
    let mut work = v
        .host_edit(b"/data")
        .unwrap()
        .into_work::<_, Vec<u8>>(&v, reader);
    let layout = work.layout();
    let admission = layout.write().try_enter().ok().unwrap();
    assert!(work
        .run(&admission, || false, |_, _| unreachable!())
        .unwrap()
        .is_none());
    drop(admission);
    assert!(work.read.as_ref().unwrap().writer().len() >= 4096);
    let staged_bytes = v.capacity().used_bytes;
    maps[0].write(0, &[99]).unwrap();
    original[0] = 99;
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=max");
    let admission = layout.write().try_enter().ok().unwrap();
    assert_eq!(
        work.run(
            &admission,
            || false,
            |_, bytes| {
                assert_eq!(
                    bytes, &original,
                    "the checksum must include the mapped change"
                );
                Err(Errno(116))
            }
        )
        .unwrap_err(),
        Errno(116)
    );
    assert_eq!(
        calls.load(Relaxed),
        2,
        "the replacement stream is not restaged"
    );
    assert_eq!(v.capacity().used_bytes, staged_bytes);
    drop(admission);
    drop(work);
    assert_eq!(v.capacity().used_bytes, staged_bytes - 5);
    assert_eq!(read(&mut v, b"/data"), original);
}
#[test]
fn an_already_applied_save_needs_no_staging_space_and_a_conflict_keeps_the_original() {
    for already in [true, false] {
        let mut v = Vfs::default();
        v.import_file(b"/data", b"done".to_vec()).unwrap();
        v.set_storage_limits(StorageLimits {
            file_bytes: 4,
            nodes: 128,
        })
        .unwrap();
        let mut work = v
            .host_edit(b"/data")
            .unwrap()
            .into_work::<_, Vec<u8>>(&v, &b"done"[..]);
        let admission = work.layout().write().try_enter().ok().unwrap();
        let result = work.run(
            &admission,
            || false,
            |_, bytes| {
                assert_eq!(bytes, b"done");
                Ok(already)
            },
        );
        if already {
            assert!(result.unwrap().is_some());
        } else {
            assert_eq!(result.unwrap_err(), Errno(28));
        }
        drop(admission);
        drop(work);
        assert_eq!(read(&mut v, b"/data"), b"done");
        assert_eq!(v.capacity().used_bytes, 4);
    }
}
