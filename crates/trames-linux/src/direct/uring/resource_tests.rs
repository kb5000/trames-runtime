// SPDX-License-Identifier: GPL-3.0-or-later
//! SQE origins survive missing payloads, migration and another observer's pump.
use super::*;
use crate::uring::tests::{add, cq, sqe};
use std::sync::Mutex;
use trames_memory::{Memory, Permissions, PAGE_SIZE};

struct Store(std::path::PathBuf);
impl Store {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "trames-uring-origin-{}-{}",
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
#[derive(Default)]
struct Queue(Mutex<Vec<(trames_vfs::FileWork, Arc<crate::FileResult>)>>);
impl FileExecutor for Queue {
    fn submit_file(&self, work: trames_vfs::FileWork, result: Arc<crate::FileResult>) {
        self.0.lock().unwrap().push((work.queued(), result));
    }
}
impl Queue {
    fn run(&self) {
        let (work, result) = self.0.lock().unwrap().remove(0);
        std::thread::spawn(move || result.complete(work.run()))
            .join()
            .unwrap();
    }
}
struct Wake;
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn write(v: &mut Vfs, path: &[u8], bytes: &[u8]) {
    let fd = v.open_at(-100, path, 2, 0).unwrap();
    assert_eq!(v.write(fd, bytes).unwrap(), bytes.len());
    v.close(fd).unwrap();
}
fn text(v: &mut Vfs, path: &[u8]) -> String {
    let fd = v.open_at(-100, path, 0, 0).unwrap();
    let bytes = v.pread(fd, 4096, 0).unwrap();
    v.close(fd).unwrap();
    String::from_utf8(bytes).unwrap()
}
fn fixture(store: &Store) -> (Linux, Memory, u32, Arc<Uring>, u32) {
    let mut linux = Linux::new(0x100000);
    linux.vfs = Vfs::open_disk(&store.0, Default::default()).unwrap();
    linux.vfs.set_runtime_info(1, Default::default());
    linux
        .vfs
        .import_file(
            b"/data",
            [vec![1; 4096], vec![2; 4096], vec![3; 4096]].concat(),
        )
        .unwrap();
    linux.vfs.import_file(b"/replacement", Vec::new()).unwrap();
    let file = linux.vfs.open_at(-100, b"/data", 2, 0).unwrap();
    let (fd, ring) = linux.vfs.uring_create(8, 16).unwrap();
    let mut memory = Memory::default();
    memory.map(0x1000, 0x9000, Permissions::RW).unwrap();
    for (address, offset, length) in [
        (0x10000, 0, ring.ring_bytes),
        (0x20000, 0x10000000, ring.sqe_bytes),
    ] {
        memory
            .map_backed(
                address,
                linux
                    .vfs
                    .mapping_pages(fd, offset, length, true, true)
                    .unwrap(),
                true,
                Permissions::RW,
                false,
            )
            .unwrap();
    }
    write(
        &mut linux.vfs,
        b"/sys/fs/cgroup/cgroup.subtree_control",
        b"+memory +io",
    );
    for name in [b"/sys/fs/cgroup/a".as_slice(), b"/sys/fs/cgroup/b"] {
        linux.vfs.mkdir_at(-100, name, 0o755).unwrap();
    }
    write(
        &mut linux.vfs,
        b"/sys/fs/cgroup/a/io.max",
        b"253:1 riops=1 wiops=1",
    );
    write(&mut linux.vfs, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    (linux, memory, fd, ring, file)
}
fn source(linux: &Linux, memory: &Memory, queue: &Arc<Queue>) -> DirectSyscalls {
    DirectSyscalls::new(linux.vfs.direct_descriptors())
        .with_membership(linux.vfs.shared_files())
        .with_paths(linux.vfs.path_queries())
        .with_resources(linux.vfs.descriptor_factory())
        .with_urings(
            UringEpoch::default()
                .capture(&linux.vfs, memory.instruction_identity().0, 1)
                .with_actor(linux.uring_actor_root()),
        )
        .with_file_executor(queue.clone())
}
fn enter(source: &DirectSyscalls, fd: u32, memory: &mut Memory, wake: &Arc<dyn IoWake>) {
    assert!(matches!(
        source.start(
            426,
            [fd as u64, 1, 0, 0, 0, 0],
            memory,
            1,
            &Arc::downgrade(wake),
            None
        ),
        Some(IoAttempt::Complete(Ok(1)))
    ));
}
fn operation(op: u8, fd: u32, address: u64, count: u32) -> [u8; 64] {
    let mut sqe = sqe(op, fd, 123);
    sqe[16..24].copy_from_slice(&address.to_le_bytes());
    sqe[24..28].copy_from_slice(&count.to_le_bytes());
    sqe
}
fn pump(ring: &Uring, memory: &mut Memory, observer: &UringActor) {
    let owner = memory.instruction_identity().0;
    ring.progress_with(memory, owner, 1, &mut |request, memory, selected| {
        observer.execute(ring, request, memory, selected)
    });
    ring.flush(&mut ring.state.lock().unwrap()).unwrap();
}
#[test]
fn setup_keeps_its_original_group_when_parameter_import_precedes_a_cow_output_wait() {
    let store = Store::new();
    let (mut linux, mut memory, _, _, _) = fixture(&store);
    let queue = Arc::new(Queue::default());
    let source = source(&linux, &memory, &queue);
    memory.unmap(0x3000, PAGE_SIZE).unwrap();
    let page = super::super::file::copyout_tests::install(&mut memory, 0x3000);
    memory.write(0x2ffc, &[0; 4]).unwrap();
    let snapshot = memory.try_fork().unwrap();
    let args = [4, 0x2ffc, 0, 0, 0, 0];
    assert!(source
        .invoke_creation_for(425, args, &mut memory, 1)
        .is_none());
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let IoAttempt::Blocked(wait) = source
        .start(425, args, &mut memory, 1, &Arc::downgrade(&wake), None)
        .unwrap()
    else {
        panic!("original setup parameter wait")
    };
    write(&mut linux.vfs, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
    let task = linux.vfs.cgroup_task(1).unwrap();
    let _other = task.resource_scope();
    page.finish();
    let IoAttempt::Complete(Ok(fd)) = source.resume(wait, &mut memory) else {
        panic!("publish the original prepared ring")
    };
    assert_eq!(linux.vfs.uring(fd as u32).unwrap().entries, 4);
    assert_eq!(memory.read_array::<4>(0x2ffc), Ok(4u32.to_le_bytes()));
    assert_eq!(snapshot.read_array::<4>(0x2ffc), Ok([0; 4]));
    assert!(
        text(&mut linux.vfs, b"/sys/fs/cgroup/a/memory.current")
            .trim()
            .parse::<u64>()
            .unwrap()
            >= PAGE_SIZE
    );
    assert_eq!(
        text(&mut linux.vfs, b"/sys/fs/cgroup/b/memory.current"),
        "0\n"
    );
}
#[test]
fn fixed_and_descriptor_ring_pins_keep_the_registration_origin_through_import_and_retirement() {
    for opcode in [0, 22] {
        for cancel in [false, true] {
            let store = Store::new();
            let (mut linux, mut memory, fd, ring, _) = fixture(&store);
            let queue = Arc::new(Queue::default());
            let source = source(&linux, &memory, &queue);
            memory.unmap(0x3000, PAGE_SIZE).unwrap();
            let page = super::super::file::copyout_tests::install(&mut memory, 0x3000);
            memory.write_array(0x2ff8, 0x5000u64.to_le_bytes()).unwrap();
            let wake: Arc<dyn IoWake> = Arc::new(Wake);
            let target = Arc::downgrade(&wake);
            let IoAttempt::Blocked(wait) = source
                .start(
                    427,
                    [fd as u64, opcode, 0x2ff8, 1, 0, 0],
                    &mut memory,
                    1,
                    &target,
                    None,
                )
                .unwrap()
            else {
                panic!("registration imports its original descriptor")
            };
            write(&mut linux.vfs, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
            let task = linux.vfs.cgroup_task(1).unwrap();
            let other = task.resource_scope();
            let mut caller_bytes = 0;
            if cancel {
                drop(wait);
                assert!(ring.state.lock().unwrap().buffers.is_none());
                assert!(ring.state.lock().unwrap().provided.is_empty());
                assert_eq!(
                    text(&mut linux.vfs, b"/sys/fs/cgroup/a/memory.current"),
                    "0\n"
                );
            } else {
                page.finish();
                // Complete the still-unread tail without allocating an
                // unrelated guest page under the resume worker's group.
                if opcode == 0 {
                    memory.write_array(0x3000, PAGE_SIZE.to_le_bytes()).unwrap();
                } else {
                    memory.write_array(0x3000, 128u32.to_le_bytes()).unwrap();
                    memory.write_array(0x3004, 7u16.to_le_bytes()).unwrap();
                }
                caller_bytes = PAGE_SIZE;
                assert!(matches!(
                    source.resume(wait, &mut memory),
                    IoAttempt::Complete(Ok(0))
                ));
                assert_eq!(
                    text(&mut linux.vfs, b"/sys/fs/cgroup/a/memory.current"),
                    "4096\n"
                );
                // A real pin, rather than a numeric charge, survives unmap.
                memory.unmap(0x5000, PAGE_SIZE).unwrap();
                assert_eq!(
                    text(&mut linux.vfs, b"/sys/fs/cgroup/a/memory.current"),
                    "4096\n"
                );
                let args = if opcode == 0 {
                    [fd as u64, 1, 0, 0, 0, 0]
                } else {
                    memory.write(0x1800, &[0; 40]).unwrap();
                    caller_bytes += PAGE_SIZE;
                    memory.write_array(0x180c, 7u16.to_le_bytes()).unwrap();
                    [fd as u64, 23, 0x1800, 1, 0, 0]
                };
                assert!(matches!(
                    source.start(427, args, &mut memory, 1, &target, None),
                    Some(IoAttempt::Complete(Ok(0)))
                ));
                assert_eq!(
                    text(&mut linux.vfs, b"/sys/fs/cgroup/a/memory.current"),
                    "0\n"
                );
            }
            assert_eq!(
                text(&mut linux.vfs, b"/sys/fs/cgroup/b/memory.current"),
                format!("{caller_bytes}\n")
            );
            // The caller's explicit parameter write allocated its own input
            // page. Registration must not add another allocation to that group.
            // All temporary resource scopes restore the caller's live origin.
            memory.write(0x7000, &[1]).unwrap();
            assert_eq!(
                text(&mut linux.vfs, b"/sys/fs/cgroup/b/memory.current"),
                format!("{}\n", caller_bytes + PAGE_SIZE)
            );
            drop(other);
        }
    }
}
#[test]
fn getevents_control_fault_keeps_the_original_origin_for_later_timeout_page_in() {
    let store = Store::new();
    let (mut linux, mut memory, fd, _, _) = fixture(&store);
    linux.vfs.import_file(b"/timeout", vec![0; 16]).unwrap();
    let timeout = linux.vfs.open_at(-100, b"/timeout", 0, 0).unwrap();
    memory.unmap(0x5000, PAGE_SIZE).unwrap();
    memory
        .map_backed(
            0x5000,
            linux
                .vfs
                .mapping_pages(timeout, 0, PAGE_SIZE, false, false)
                .unwrap(),
            false,
            Permissions::R,
            false,
        )
        .unwrap();
    memory.unmap(0x3000, PAGE_SIZE).unwrap();
    let page = super::super::file::copyout_tests::install(&mut memory, 0x3000);
    memory.write_array(0x2ff8, 0u64.to_le_bytes()).unwrap();
    let queue = Arc::new(Queue::default());
    let source = source(&linux, &memory, &queue);
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let IoAttempt::Blocked(wait) = source
        .start(
            426,
            [fd as u64, 0, 1, 9, 0x2ff8, 24],
            &mut memory,
            1,
            &Arc::downgrade(&wake),
            None,
        )
        .unwrap()
    else {
        panic!("extended GETEVENTS descriptor waits before timeout import")
    };
    write(&mut linux.vfs, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
    let task = linux.vfs.cgroup_task(1).unwrap();
    let _other = task.resource_scope();
    page.finish();
    memory.write_array(0x3008, 0x5000u64.to_le_bytes()).unwrap();
    let caller_memory = text(&mut linux.vfs, b"/sys/fs/cgroup/b/memory.current");
    assert_eq!(caller_memory, "4096\n");
    assert!(matches!(
        source.resume(wait, &mut memory),
        IoAttempt::Complete(Err(Errno(62)))
    ));
    let a = text(&mut linux.vfs, b"/sys/fs/cgroup/a/io.stat");
    assert!(a.split_whitespace().any(|word| word == "rios=1"));
    assert!(a.split_whitespace().any(|word| word == "rbytes=16"));
    let b = text(&mut linux.vfs, b"/sys/fs/cgroup/b/io.stat");
    assert!(!b
        .split_whitespace()
        .any(|word| word.starts_with("rios=") && word != "rios=0"));
    assert_eq!(
        text(&mut linux.vfs, b"/sys/fs/cgroup/b/memory.current"),
        caller_memory
    );
    assert_eq!(
        text(&mut linux.vfs, b"/sys/fs/cgroup/a/memory.current"),
        "4096\n"
    );
}
#[test]
fn uring_payload_fault_keeps_source_origin_across_observer_handoff_or_cancellation() {
    for cancel in [false, true] {
        let store = Store::new();
        let (mut linux, mut memory, fd, ring, file) = fixture(&store);
        memory.unmap(0x3000, PAGE_SIZE).unwrap();
        let page = crate::direct::file::copyout_tests::install(&mut memory, 0x3000);
        let queue = Arc::new(Queue::default());
        let source = source(&linux, &memory, &queue);
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        add(&mut memory, &ring, operation(23, file, 0x3000, 7));
        enter(&source, fd, &mut memory, &wake);
        assert!(queue.0.lock().unwrap().is_empty());
        assert_eq!(ring.state.lock().unwrap().pending.len(), 1);
        write(&mut linux.vfs, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
        linux.vfs.close(file).unwrap();
        assert_eq!(
            linux.vfs.open_at(-100, b"/replacement", 2, 0).unwrap(),
            file
        );
        drop(source);
        let task = linux.vfs.cgroup_task(1).unwrap();
        let _other = task.resource_scope();
        let observer = UringActor::default();
        if cancel {
            linux
                .uring_actor_root()
                .get()
                .unwrap()
                .cancel_task(memory.instruction_identity().0, 1);
        }
        page.finish();
        memory.write(0x3000, b"written").unwrap();
        pump(&ring, &mut memory, &observer);
        if cancel {
            assert!(queue.0.lock().unwrap().is_empty());
            assert_eq!(cq(&mut memory, &ring), (123, -125));
        } else {
            assert_eq!(queue.0.lock().unwrap().len(), 1);
            queue.run();
            pump(&ring, &mut memory, &observer);
            assert_eq!(cq(&mut memory, &ring), (123, 7));
            let a = text(&mut linux.vfs, b"/sys/fs/cgroup/a/io.stat");
            assert!(a.split_whitespace().any(|word| word == "wios=1"));
            assert!(a.split_whitespace().any(|word| word == "wbytes=7"));
        }
        let original = linux.vfs.open_at(-100, b"/data", 0, 0).unwrap();
        assert_eq!(
            linux.vfs.pread(original, 7, 0).unwrap(),
            if cancel {
                [1; 7].as_slice()
            } else {
                b"written"
            }
        );
        assert!(linux.vfs.pread(file, 7, 0).unwrap().is_empty());
        let b = text(&mut linux.vfs, b"/sys/fs/cgroup/b/io.stat");
        assert!(!b
            .split_whitespace()
            .any(|word| word.starts_with("wbytes=") && word != "wbytes=0"));
        assert!(ring.state.lock().unwrap().pending.is_empty());
    }
}
#[test]
fn uring_read_keeps_io_and_memory_origins_through_resource_wait_and_observer_copyout() {
    let store = Store::new();
    let (mut linux, mut memory, fd, ring, file) = fixture(&store);
    let queue = Arc::new(Queue::default());
    let source = source(&linux, &memory, &queue);
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    add(&mut memory, &ring, operation(22, file, 0x5000, 12288));
    enter(&source, fd, &mut memory, &wake);
    queue.run();
    drop(source);
    write(&mut linux.vfs, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
    let task = linux.vfs.cgroup_task(1).unwrap();
    let _other = task.resource_scope();
    let observer = UringActor::default();
    pump(&ring, &mut memory, &observer);
    assert!(queue.0.lock().unwrap().is_empty());
    assert_eq!(ring.state.lock().unwrap().pending.len(), 1);
    let a = text(&mut linux.vfs, b"/sys/fs/cgroup/a/io.stat");
    assert!(a.split_whitespace().any(|word| word == "rios=1"));
    write(
        &mut linux.vfs,
        b"/sys/fs/cgroup/a/io.max",
        b"253:1 riops=max",
    );
    pump(&ring, &mut memory, &observer);
    queue.run();
    pump(&ring, &mut memory, &observer);
    assert_eq!(cq(&mut memory, &ring), (123, 12288));
    for (address, byte) in [(0x5000, 1), (0x6000, 2), (0x7000, 3)] {
        assert_eq!(memory.read_array::<1>(address), Ok([byte]));
    }
    let a = text(&mut linux.vfs, b"/sys/fs/cgroup/a/io.stat");
    assert!(a.split_whitespace().any(|word| word == "rios=3"));
    assert!(a.split_whitespace().any(|word| word == "rbytes=12288"));
    assert!(
        text(&mut linux.vfs, b"/sys/fs/cgroup/a/memory.current")
            .trim()
            .parse::<u64>()
            .unwrap()
            >= 12288
    );
    assert_eq!(
        text(&mut linux.vfs, b"/sys/fs/cgroup/b/memory.current"),
        "0\n"
    );
    assert!(ring.state.lock().unwrap().pending.is_empty());
}
