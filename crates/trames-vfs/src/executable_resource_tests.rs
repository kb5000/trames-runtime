// SPDX-License-Identifier: GPL-3.0-or-later
//! Actual disk admission retains exec input independently of cache residency.
use super::*;
struct Store(std::path::PathBuf);
impl Store {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "trames-exec-input-{}-{}",
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
    let out = v.pread(fd, 4096, 0).unwrap();
    v.close(fd).unwrap();
    out
}
fn rios(v: &mut Vfs) -> u64 {
    String::from_utf8(read(v, b"/sys/fs/cgroup/a/io.stat"))
        .unwrap()
        .split_whitespace()
        .find_map(|field| {
            field
                .strip_prefix("rios=")
                .map(|number| number.parse().unwrap())
        })
        .unwrap_or(0)
}
#[test]
fn executable_prefix_survives_reclaim_migration_fd_reuse_and_path_replacement() {
    let store = Store::new();
    let mut v = Vfs::open_disk(&store.0, Default::default()).unwrap();
    v.set_runtime_info(1, RuntimeInfo::default());
    let bytes = [vec![1; 4096], vec![2; 4096], vec![3; 4096]].concat();
    v.import_executable(b"/image", bytes.clone()).unwrap();
    v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/a", 0o755).unwrap();
    write(
        &mut v,
        b"/sys/fs/cgroup/cgroup.subtree_control",
        b"+memory +io",
    );
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=1");
    let task = v.cgroup_task(1).unwrap();
    let _resources = task.resource_scope();
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    let fd = v.open_at(AT_FDCWD, b"/image", 0, 0).unwrap();
    let file = v.executable_file_at(fd as i32, b"", 0x1000).unwrap();
    let access = file.begin_execution().unwrap();
    let mut input = ExecutableRead::new(file).unwrap();
    assert!(input.run().unwrap().is_none());
    assert_eq!(input.bytes.len(), 4096);
    assert_eq!(rios(&mut v), 1);
    assert!(input
        .wait()
        .unwrap()
        .deadline()
        .is_some_and(|deadline| deadline > std::time::Instant::now()));
    v.close(fd).unwrap();
    v.rename_at(AT_FDCWD, b"/image", AT_FDCWD, b"/moved", 0)
        .unwrap();
    write(&mut v, b"/sys/fs/cgroup/cgroup.procs", b"1");
    v.import_executable(b"/image", b"replacement".to_vec())
        .unwrap();
    assert_eq!(v.open_at(AT_FDCWD, b"/image", 0, 0).unwrap(), fd);
    write(&mut v, b"/sys/fs/cgroup/a/memory.reclaim", b"4096");
    assert_eq!(read(&mut v, b"/sys/fs/cgroup/a/memory.current"), b"0\n");
    assert!(input.run().unwrap().is_none());
    assert_eq!(
        rios(&mut v),
        1,
        "a pending input performs no new disk request"
    );
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 riops=max");
    assert_eq!(input.run().unwrap().unwrap(), bytes);
    assert_eq!(
        rios(&mut v),
        3,
        "the reclaimed completed prefix must not be reread"
    );
    assert_eq!(v.open_at(AT_FDCWD, b"/moved", 2, 0), Err(Errno(26)));
    drop(input);
    drop(access);
    v.open_at(AT_FDCWD, b"/moved", 2, 0).unwrap();
}
#[test]
fn cancelling_an_input_releases_its_wait_and_the_original_text_lease() {
    let store = Store::new();
    let mut v = Vfs::open_disk(&store.0, Default::default()).unwrap();
    v.set_runtime_info(1, RuntimeInfo::default());
    v.import_executable(b"/image", vec![4; 8192]).unwrap();
    write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"+io");
    v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/a", 0o755).unwrap();
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 rbps=1");
    let task = v.cgroup_task(1).unwrap();
    let _resources = task.resource_scope();
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    let file = v.executable_file_at(AT_FDCWD, b"/image", 0).unwrap();
    let access = file.begin_execution().unwrap();
    let mut input = ExecutableRead::new(file).unwrap();
    assert!(input.run().unwrap().is_none());
    let wait = Arc::downgrade(input.wait().unwrap());
    assert_eq!(rios(&mut v), 0);
    drop(input);
    drop(access);
    assert!(wait.upgrade().is_none());
    v.open_at(AT_FDCWD, b"/image", 2, 0).unwrap();
}
