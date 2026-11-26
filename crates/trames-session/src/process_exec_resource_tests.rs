// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted script/main/PT_INTERP input advances only on existing executors.
use super::*;
use trames_cpu::Cpu as TestCpu;

struct Store(std::path::PathBuf);
impl Store {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "trames-exec-resource-{}-{}",
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
struct Held(std::sync::mpsc::Sender<(Request, Arc<Pending<TestCpu>>)>);
impl Executor<TestCpu> for Held {
    fn submit_image(&self, request: Request, result: Arc<Pending<TestCpu>>) {
        self.0.send((request, result)).unwrap();
    }
}
struct Wake;
impl trames_shared::IoWake for Wake {
    fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {}
}
fn write(v: &mut trames_vfs::Vfs, path: &[u8], bytes: &[u8]) {
    let fd = v.open_at(AT_FDCWD, path, 2, 0).unwrap();
    assert_eq!(v.write(fd, bytes).unwrap(), bytes.len());
    v.close(fd).unwrap();
}
fn stats(v: &mut trames_vfs::Vfs, key: &str) -> u64 {
    let fd = v
        .open_at(AT_FDCWD, b"/sys/fs/cgroup/a/io.stat", 0, 0)
        .unwrap();
    let text = String::from_utf8(v.pread(fd, 4096, 0).unwrap()).unwrap();
    v.close(fd).unwrap();
    text.split_whitespace()
        .find_map(|field| {
            field
                .strip_prefix(key)
                .map(|number| number.parse().unwrap())
        })
        .unwrap_or(0)
}
fn process(store: &Store) -> Box<Process<TestCpu>> {
    let mut p = super::super::tests::process();
    p.linux.vfs = trames_vfs::Vfs::open_disk(&store.0, Default::default()).unwrap();
    p.linux.vfs.set_runtime_info(1, Default::default());
    write(
        &mut p.linux.vfs,
        b"/sys/fs/cgroup/cgroup.subtree_control",
        b"+io",
    );
    p.linux
        .vfs
        .mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/a", 0o755)
        .unwrap();
    p.signals
        .io
        .bind_cgroup(p.linux.vfs.cgroup_task(1).unwrap());
    write(&mut p.linux.vfs, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    p
}
fn request(p: &Process<TestCpu>, path: &[u8]) -> Request {
    Request::new(
        p,
        AT_FDCWD,
        path.to_vec(),
        vec![path.to_vec(), b"arg".to_vec()],
        Vec::new(),
        0,
        32 * 1024 * 1024,
        Instant::now(),
    )
}
fn main_elf() -> Vec<u8> {
    let mut bytes = super::tests::elf(&[0x14000000]);
    bytes.resize(768, 0);
    bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
    bytes[120..124].copy_from_slice(&3u32.to_le_bytes());
    bytes[128..136].copy_from_slice(&512u64.to_le_bytes());
    bytes[152..160].copy_from_slice(&4u64.to_le_bytes());
    bytes[512..516].copy_from_slice(b"/ld\0");
    bytes
}
#[test]
fn script_and_dynamic_loader_waits_keep_original_files_arguments_and_io_owner() {
    let store = Store::new();
    let mut p = process(&store);
    let main = main_elf();
    let mut loader = super::tests::elf(&[0x14000000]);
    loader[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN loader has its own bias.
    let script = b"#!/main --flag\n";
    p.linux
        .vfs
        .import_executable(b"/script", script.to_vec())
        .unwrap();
    p.linux
        .vfs
        .import_executable(b"/main", main.clone())
        .unwrap();
    p.linux
        .vfs
        .import_executable(b"/ld", loader.clone())
        .unwrap();
    write(
        &mut p.linux.vfs,
        b"/sys/fs/cgroup/a/io.max",
        b"253:1 riops=1",
    );
    let accepted = request(&p, b"/script");
    let pending = Arc::new(Pending::<TestCpu>::new());
    pending.complete(accepted.load());
    assert!(!pending.ready());
    assert_eq!(stats(&mut p.linux.vfs, "rios="), 1);
    let wake: Arc<dyn trames_shared::IoWake> = Arc::new(Wake);
    let signal = trames_shared::IoSignal::new(1, Arc::downgrade(&wake));
    let subscriptions = pending.subscribe(&signal);
    assert!(subscriptions
        .iter()
        .filter_map(trames_shared::IoSubscription::deadline)
        .any(|deadline| deadline > Instant::now()));
    let (send, receive) = std::sync::mpsc::channel();
    let held = Held(send);
    pending.resume(&held);
    assert!(receive.try_recv().is_err());

    write(&mut p.linux.vfs, b"/sys/fs/cgroup/cgroup.procs", b"1");
    p.linux
        .vfs
        .rename_at(AT_FDCWD, b"/main", AT_FDCWD, b"/old-main", 0)
        .unwrap();
    p.linux
        .vfs
        .import_executable(b"/main", b"invalid replacement".to_vec())
        .unwrap();
    // Grant one more original request without sleeping or a timer worker.
    write(
        &mut p.linux.vfs,
        b"/sys/fs/cgroup/a/io.max",
        b"253:1 riops=max",
    );
    write(
        &mut p.linux.vfs,
        b"/sys/fs/cgroup/a/io.max",
        b"253:1 riops=1",
    );
    assert!(signal.ready());
    assert_eq!(
        stats(&mut p.linux.vfs, "rios="),
        1,
        "a resource callback does no file IO"
    );
    pending.resume(&held);
    let (accepted, result) = receive.try_recv().unwrap();
    assert!(Arc::ptr_eq(&result, &pending));
    result.complete(accepted.load());
    assert!(!pending.ready());
    assert_eq!(stats(&mut p.linux.vfs, "rios="), 2);
    assert_eq!(
        stats(&mut p.linux.vfs, "rbytes="),
        (script.len() + main.len()) as u64
    );
    p.linux
        .vfs
        .rename_at(AT_FDCWD, b"/ld", AT_FDCWD, b"/old-ld", 0)
        .unwrap();
    p.linux
        .vfs
        .import_executable(b"/ld", b"invalid loader replacement".to_vec())
        .unwrap();
    write(
        &mut p.linux.vfs,
        b"/sys/fs/cgroup/a/io.max",
        b"253:1 riops=max",
    );
    pending.resume(&held);
    let (accepted, result) = receive.try_recv().unwrap();
    result.complete(accepted.load());
    assert!(pending.ready());
    let image = pending.take().unwrap().unwrap();
    assert_eq!(
        image.linux.arguments,
        vec![
            b"/main".to_vec(),
            b"--flag".to_vec(),
            b"/script".to_vec(),
            b"arg".to_vec()
        ]
    );
    assert_eq!(image.linux.executable_path, b"/old-main");
    assert_eq!(stats(&mut p.linux.vfs, "rios="), 3);
    assert_eq!(
        stats(&mut p.linux.vfs, "rbytes="),
        (script.len() + main.len() + loader.len()) as u64
    );
    assert!(
        receive.try_recv().is_err(),
        "each resume submits only the retained original once"
    );
}
#[test]
fn cancelling_a_pending_image_releases_its_input_text_lease_and_cannot_queue_a_retry() {
    let store = Store::new();
    let mut p = process(&store);
    p.linux.vfs.import_executable(b"/main", main_elf()).unwrap();
    write(
        &mut p.linux.vfs,
        b"/sys/fs/cgroup/a/io.max",
        b"253:1 rbps=1",
    );
    let pending = Arc::new(Pending::<TestCpu>::new());
    pending.complete(request(&p, b"/main").load());
    assert!(!pending.ready());
    assert_eq!(
        p.linux.vfs.open_at(AT_FDCWD, b"/main", 2, 0),
        Err(Errno(26))
    );
    let (send, receive) = std::sync::mpsc::channel();
    let held = Held(send);
    pending.resume(&held);
    assert!(receive.try_recv().is_err());
    drop(pending);
    p.linux.vfs.open_at(AT_FDCWD, b"/main", 2, 0).unwrap();
    write(
        &mut p.linux.vfs,
        b"/sys/fs/cgroup/a/io.max",
        b"253:1 rbps=max",
    );
    assert!(receive.try_recv().is_err());
    assert_eq!(stats(&mut p.linux.vfs, "rios="), 0);
}
