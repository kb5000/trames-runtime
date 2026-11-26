// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};
#[path = "file_read_resource_tests.rs"]
mod read_resources;
struct Queue(std::sync::mpsc::Sender<(trames_vfs::FileWork, Arc<FileResult>)>);
impl FileExecutor for Queue {
    fn submit_file(&self, work: trames_vfs::FileWork, result: Arc<FileResult>) {
        result.begin();
        assert!(self.0.send((work.queued(), result)).is_ok());
    }
}
#[derive(Default)]
struct Target(std::sync::atomic::AtomicUsize);
impl IoWake for Target {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
fn t() -> Arc<dyn IoWake> {
    Arc::new(Target::default())
}

fn fuse_reply(v: &mut trames_vfs::Vfs, fd: u32, request: &[u8], payload: &[u8]) {
    let mut bytes = Vec::new();
    bytes.extend(((16 + payload.len()) as u32).to_le_bytes());
    bytes.extend(0i32.to_le_bytes());
    bytes.extend(&request[8..16]);
    bytes.extend(payload);
    assert_eq!(v.write(fd, &bytes), Ok(bytes.len()));
}
fn fuse_error(v: &mut trames_vfs::Vfs, fd: u32, request: &[u8], error: i32) {
    let mut bytes = 16u32.to_le_bytes().to_vec();
    bytes.extend((-error).to_le_bytes());
    bytes.extend(&request[8..16]);
    assert_eq!(v.write(fd, &bytes), Ok(bytes.len()));
}
pub(in crate::direct) fn mount_socket_fuse(v: &mut trames_vfs::Vfs) -> u32 {
    v.set_runtime_info(1, trames_vfs::RuntimeInfo::default());
    v.mkdir_at(-100, b"/mnt", 0o755).unwrap();
    let daemon = v.open_at(-100, b"/dev/fuse", 2, 0).unwrap();
    v.mount(
        None,
        b"/mnt",
        Some(b"fuse"),
        0,
        Some(format!("fd={daemon},rootmode=40755,user_id=0,group_id=0").as_bytes()),
    )
    .unwrap();
    let init = fuse_receive(v, daemon, 26);
    let mut version = [0; 64];
    version[..4].copy_from_slice(&7u32.to_le_bytes());
    version[4..8].copy_from_slice(&31u32.to_le_bytes());
    fuse_reply(v, daemon, &init, &version);
    daemon
}
pub(in crate::direct) fn fuse_socket_error_step(
    v: &mut trames_vfs::Vfs,
    daemon: u32,
    bind: bool,
) -> bool {
    let request = v.read(daemon, 128 * 1024).unwrap();
    match u32::from_le_bytes(request[4..8].try_into().unwrap()) {
        3 => {
            let mut attr = [0; 104];
            attr[..8].copy_from_slice(&1u64.to_le_bytes());
            attr[16..24].copy_from_slice(&1u64.to_le_bytes());
            attr[76..80].copy_from_slice(&0o40755u32.to_le_bytes());
            fuse_reply(v, daemon, &request, &attr);
            false
        }
        1 if bind => {
            fuse_error(v, daemon, &request, 2);
            false
        }
        1 | 8 => {
            fuse_error(v, daemon, &request, 11);
            true
        }
        opcode => panic!("unexpected socket pathname opcode {opcode}"),
    }
}

#[test]
fn fuse_socket_namespace_eagain_completes_instead_of_waiting_or_replaying() {
    for number in [200, 203, 206, 211, 269] {
        let mut v = trames_vfs::Vfs::default();
        v.set_runtime_info(1, trames_vfs::RuntimeInfo::default());
        let daemon = mount_socket_fuse(&mut v);
        let fd = v
            .local_create(if number >= 206 { 2 } else { 1 }, 0)
            .unwrap();
        let direct = DirectSyscalls::new(v.direct_descriptors())
            .with_resources(v.descriptor_factory())
            .with_paths(v.path_queries());
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let address = b"\x01\0/mnt/socket\0";
        memory.write(0x1100, address).unwrap();
        memory.write(0x1200, b"data").unwrap();
        memory.write(0x1300, &0x1200u64.to_le_bytes()).unwrap();
        memory.write(0x1308, &4u64.to_le_bytes()).unwrap();
        memory.write(0x1400, &0x1100u64.to_le_bytes()).unwrap();
        memory
            .write(0x1408, &(address.len() as u32).to_le_bytes())
            .unwrap();
        memory.write(0x1410, &0x1300u64.to_le_bytes()).unwrap();
        memory.write(0x1418, &1u64.to_le_bytes()).unwrap();
        let args = match number {
            200 | 203 => [fd as u64, 0x1100, address.len() as u64, 0, 0, 0],
            206 => [fd as u64, 0x1200, 4, 0, 0x1100, address.len() as u64],
            211 => [fd as u64, 0x1400, 0, 0, 0, 0],
            _ => [fd as u64, 0x1400, 1, 0, 0, 0],
        };
        let target = t();
        let mut attempt = if number < 206 {
            direct
                .start_socket_control(number, args, &mut memory, 1, &Arc::downgrade(&target))
                .unwrap()
        } else {
            direct
                .start_local_message(number, args, &mut memory, 1, &Arc::downgrade(&target))
                .unwrap()
        };
        let mut terminal = false;
        for _ in 0..8 {
            terminal = fuse_socket_error_step(&mut v, daemon, number == 200);
            attempt = resume_fuse(attempt, number, args, &mut memory, &target);
            if terminal {
                break;
            }
        }
        assert!(terminal);
        assert!(
            matches!(attempt, IoAttempt::Complete(Err(Errno(11)))),
            "namespace errno must terminate syscall {number}"
        );
        assert_eq!(
            v.read(daemon, 8192),
            Err(Errno(11)),
            "no replayed lookup/mknod"
        );
    }
}
fn fuse_receive(v: &mut trames_vfs::Vfs, fd: u32, opcode: u32) -> Vec<u8> {
    let bytes = v.read(fd, 128 * 1024).unwrap();
    assert_eq!(&bytes[4..8], &opcode.to_le_bytes());
    bytes
}
fn resume_fuse(
    attempt: IoAttempt,
    number: u32,
    args: [u64; 6],
    memory: &mut Memory,
    target: &Arc<dyn IoWake>,
) -> IoAttempt {
    let IoAttempt::Blocked(wait) = attempt else {
        panic!("daemon request must park the source")
    };
    let pending = wait.file_pending().unwrap();
    drop(wait);
    DirectSyscalls::default().start_retained_file(
        pending,
        number,
        args,
        memory,
        1,
        &Arc::downgrade(target),
    )
}

#[test]
fn fuse_path_only_bind_fstat_parks_one_original_request_across_fd_reuse() {
    let mut v = trames_vfs::Vfs::default();
    v.set_runtime_info(1, trames_vfs::RuntimeInfo::default());
    v.mkdir_at(-100, b"/mnt", 0o755).unwrap();
    v.import_file(b"/bound", Vec::new()).unwrap();
    let daemon = v.open_at(-100, b"/dev/fuse", 2, 0).unwrap();
    v.mount(
        None,
        b"/mnt",
        Some(b"fuse"),
        0,
        Some(format!("fd={daemon},rootmode=40755,user_id=0,group_id=0").as_bytes()),
    )
    .unwrap();
    let init = fuse_receive(&mut v, daemon, 26);
    let mut version = [0; 64];
    version[..4].copy_from_slice(&7u32.to_le_bytes());
    version[4..8].copy_from_slice(&31u32.to_le_bytes());
    fuse_reply(&mut v, daemon, &init, &version);
    let paths = v.path_queries();
    let work = paths.namespace_work(trames_vfs::NamespaceCall::Mount {
        source: Some(b"/mnt/file".to_vec()),
        target: b"/bound".to_vec(),
        kind: None,
        flags: 4096,
        data: None,
    });
    let trames_vfs::FileOutcome::Waiting(work) = work.run() else {
        panic!("lookup")
    };
    let lookup = fuse_receive(&mut v, daemon, 1);
    let mut entry = [0; 128];
    entry[..8].copy_from_slice(&10u64.to_le_bytes());
    entry[40..48].copy_from_slice(&210u64.to_le_bytes());
    entry[100..104].copy_from_slice(&0o100644u32.to_le_bytes());
    fuse_reply(&mut v, daemon, &lookup, &entry);
    let trames_vfs::FileOutcome::Complete(reply) = work.run() else {
        panic!("bind")
    };
    assert!(matches!(reply.result, Ok(trames_vfs::FileValue::Count(0))));
    let fd = v.open_at(-100, b"/bound", trames_vfs::O_PATH, 0).unwrap();
    let files = v.shared_files();
    let direct = DirectSyscalls::default()
        .with_paths(v.path_queries())
        .with_membership(files.clone());
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    let target = t();
    let args = [fd as u64, 0x1000, 0, 0, 0, 0];
    let attempt = direct
        .start_file_call(80, args, &mut memory, 1, &Arc::downgrade(&target))
        .unwrap();
    assert!(
        matches!(&attempt, IoAttempt::Blocked(_)),
        "daemon metadata must park, not request file layout"
    );
    let getattr = fuse_receive(&mut v, daemon, 3);
    assert_eq!(&getattr[16..24], &10u64.to_le_bytes());
    assert_eq!(&getattr[32..36], &1u32.to_le_bytes());
    files.close_range(fd, fd, 0, 1).unwrap();
    assert_eq!(v.open_at(-100, b"/replacement", 0x42, 0o600).unwrap(), fd);
    let mut attr = [0; 104];
    attr[16..].copy_from_slice(&entry[40..]);
    fuse_reply(&mut v, daemon, &getattr, &attr);
    assert!(matches!(
        resume_fuse(attempt, 80, args, &mut memory, &target),
        IoAttempt::Complete(Ok(0))
    ));
    assert_eq!(memory.read_u64(0x1008).unwrap(), 210);
    assert_eq!(
        v.read(daemon, 8192),
        Err(trames_vfs::Errno(11)),
        "no replayed GETATTR"
    );
}

#[test]
fn fuse_getdents_parks_and_preserves_original_ofd_through_fd_reuse_and_partial_copy() {
    let mut v = trames_vfs::Vfs::default();
    v.set_runtime_info(1, trames_vfs::RuntimeInfo::default());
    v.mkdir_at(-100, b"/mnt", 0o755).unwrap();
    let daemon = v.open_at(-100, b"/dev/fuse", 2, 0).unwrap();
    v.mount(
        None,
        b"/mnt",
        Some(b"fuse"),
        0,
        Some(format!("fd={daemon},rootmode=40755,user_id=0,group_id=0").as_bytes()),
    )
    .unwrap();
    let init = fuse_receive(&mut v, daemon, 26);
    let mut version = [0; 64];
    version[..4].copy_from_slice(&7u32.to_le_bytes());
    version[4..8].copy_from_slice(&31u32.to_le_bytes());
    fuse_reply(&mut v, daemon, &init, &version);
    let mut memory = Memory::default();
    memory.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
    memory.write(0x1000, b"/mnt\0").unwrap();
    let target = t();
    let files = v.shared_files();
    let direct = DirectSyscalls::default()
        .with_paths(v.path_queries())
        .with_membership(files.clone());
    let open_args = [
        (-100i64) as u64,
        0x1000,
        trames_vfs::O_DIRECTORY as u64,
        0,
        0,
        0,
    ];
    let open = direct
        .start_file_call(56, open_args, &mut memory, 1, &Arc::downgrade(&target))
        .unwrap();
    let getattr = fuse_receive(&mut v, daemon, 3);
    let mut attr = [0; 104];
    attr[16..24].copy_from_slice(&1u64.to_le_bytes());
    attr[76..80].copy_from_slice(&0o40755u32.to_le_bytes());
    fuse_reply(&mut v, daemon, &getattr, &attr);
    let open = resume_fuse(open, 56, open_args, &mut memory, &target);
    match &open {
        IoAttempt::Blocked(_) => {}
        IoAttempt::Complete(value) => panic!("opendir returned early: {value:?}"),
        _ => panic!("opendir requested unexpected boundary"),
    }
    let opendir = fuse_receive(&mut v, daemon, 27);
    let mut handle = [0; 16];
    handle[..8].copy_from_slice(&123u64.to_le_bytes());
    fuse_reply(&mut v, daemon, &opendir, &handle);
    let IoAttempt::Complete(Ok(fd)) = resume_fuse(open, 56, open_args, &mut memory, &target) else {
        panic!("directory publication")
    };
    let fd = fd as u32;
    let dup = files.duplicate(fd, 0, false).unwrap().unwrap();
    let args = [fd as u64, 0x3000 - 24, 64, 0, 0, 0];
    let read = direct
        .start_file_call(61, args, &mut memory, 1, &Arc::downgrade(&target))
        .unwrap();
    let readdir = fuse_receive(&mut v, daemon, 28);
    assert_eq!(&readdir[40..48], &123u64.to_le_bytes());
    files.close_range(fd, fd, 0, 1).unwrap();
    assert_eq!(v.open_at(-100, b"/replacement", 0x42, 0o600).unwrap(), fd);
    let mut entries = Vec::new();
    for (ino, cookie) in [(42u64, 9u64), (43, 777)] {
        let mut entry = vec![0; 32];
        entry[..8].copy_from_slice(&ino.to_le_bytes());
        entry[8..16].copy_from_slice(&cookie.to_le_bytes());
        entry[16..20].copy_from_slice(&1u32.to_le_bytes());
        entry[20..24].copy_from_slice(&8u32.to_le_bytes());
        entry[24] = b'a';
        entries.extend(entry);
    }
    fuse_reply(&mut v, daemon, &readdir, &entries);
    assert!(matches!(
        resume_fuse(read, 61, args, &mut memory, &target),
        IoAttempt::Complete(Ok(24))
    ));
    assert_eq!(memory.read_u64(0x3000 - 24 + 8).unwrap(), 9);
    assert!(matches!(
        direct.start_file_call(
            62,
            [dup as u64, 0, 1, 0, 0, 0],
            &mut memory,
            1,
            &Arc::downgrade(&target)
        ),
        Some(IoAttempt::Complete(Ok(9)))
    ));
    assert_eq!(
        v.seek(fd, 0, 1),
        Ok(0),
        "replacement description must stay untouched"
    );
}
#[test]
fn original_copy_range_validates_requested_overflow_before_shortening_or_advancing() {
    let mut l = Linux::new(0x100000);
    l.vfs.import_file(b"/input", b"unchanged".to_vec()).unwrap();
    let from = l.vfs.open_at(-100, b"/input", 0, 0).unwrap();
    let to = l.vfs.open_at(-100, b"/output", 0x42, 0o600).unwrap();
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let direct = DirectSyscalls::new(l.vfs.direct_descriptors())
        .with_paths(l.vfs.path_queries())
        .with_resources(l.vfs.descriptor_factory())
        .with_file_executor(Arc::new(Queue(send)));
    let target = t();
    for (input, output, count, error) in [
        (u64::MAX, 0, 1, 75),
        (0, u64::MAX, 1, 75),
        (1, 0, u64::MAX, 75),
        (0, 1, u64::MAX, 75),
        (u64::MAX - 1, 0, 1, 22),
        (u64::MAX, 0, 0, 22),
    ] {
        memory.write_array(0x1000, input.to_le_bytes()).unwrap();
        memory.write_array(0x1008, output.to_le_bytes()).unwrap();
        let args = [from as u64, 0x1000, to as u64, 0x1008, count, 0];
        let expected = Err(Errno(error));
        assert_eq!(
            l.syscall(
                285,
                args,
                &mut memory,
                &mut crate::CapturedOutput::default()
            ),
            expected
        );
        let attempt = direct.start_file_call(285, args, &mut memory, 1, &Arc::downgrade(&target));
        let result = match attempt {
            Some(IoAttempt::Complete(value)) => value,
            Some(IoAttempt::Blocked(wait)) => {
                let pending = wait.file_pending().unwrap();
                let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
                std::thread::spawn(move || result.complete(work.run()))
                    .join()
                    .unwrap();
                match direct.start_retained_file(
                    pending,
                    285,
                    args,
                    &mut memory,
                    1,
                    &Arc::downgrade(&target),
                ) {
                    IoAttempt::Complete(value) => value,
                    _ => panic!("completed original copy"),
                }
            }
            None => panic!("original copy admission"),
            Some(_) => panic!("original copy returned an unrelated operation"),
        };
        assert_eq!(result, expected, "{input} {output} {count}");
        assert_eq!(memory.read_u64(0x1000).unwrap(), input);
        assert_eq!(memory.read_u64(0x1008).unwrap(), output);
        assert_eq!(l.vfs.seek(from, 0, 1), Ok(0));
        assert_eq!(l.vfs.seek(to, 0, 1), Ok(0));
        assert_eq!(l.vfs.pread(to, 9, 0).unwrap(), b"");
    }
}
#[test]
fn native_memfd_creation_retains_original_name_files_credentials_and_handoff() {
    let mut v = trames_vfs::Vfs::default();
    v.credentials = trames_vfs::Credentials::user(1000, 1001);
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.write(0x1000, b"original\0").unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let target = t();
    let direct = DirectSyscalls::default()
        .with_paths(v.path_queries())
        .with_file_executor(Arc::new(Queue(send)));
    let args = [0x1000, 3, 0, 0, 0, 0];
    let Some(IoAttempt::Blocked(wait)) =
        direct.start_file_call(279, args, &mut memory, 1, &Arc::downgrade(&target))
    else {
        panic!("native memory-file allocation must return its CPU slot")
    };
    let pending = wait.file_pending().unwrap();
    assert!(!pending.interruptible());
    drop((wait, direct, target));
    memory.unmap(0x1000, PAGE_SIZE).unwrap();
    v.credentials = Default::default();
    let original_counter = v.eventfd(99, 0).unwrap();
    let mut unrelated = trames_vfs::Vfs::default();
    assert_eq!(
        unrelated.memfd_create(b"unrelated", 0).unwrap(),
        original_counter
    );
    let target = t();
    let IoAttempt::Blocked(wait) = DirectSyscalls::default().start_retained_file(
        pending,
        279,
        args,
        &mut memory,
        1,
        &Arc::downgrade(&target),
    ) else {
        panic!("retain accepted native allocation")
    };
    let pending = wait.file_pending().unwrap();
    let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    std::thread::spawn(move || result.complete(work.run()))
        .join()
        .unwrap();
    assert!(wait.signal.ready());
    drop(wait);
    let IoAttempt::Complete(Ok(fd)) = DirectSyscalls::default().start_retained_file(
        pending,
        279,
        args,
        &mut memory,
        1,
        &Arc::downgrade(&target),
    ) else {
        panic!("commit accepted original memory file")
    };
    let fd = fd as u32;
    assert_ne!(fd, original_counter);
    assert_eq!(
        v.fd_kind(fd).unwrap(),
        trames_vfs::FdKind::Node(b"/memfd:original".to_vec())
    );
    assert_eq!(v.flags(fd).unwrap(), 2 | trames_vfs::O_CLOEXEC);
    assert_eq!(v.seals(fd, None), Ok(0));
    let stat = v.stat_fd(fd).unwrap();
    assert_eq!(u32::from_le_bytes(stat[24..28].try_into().unwrap()), 1000);
    assert_eq!(u32::from_le_bytes(stat[28..32].try_into().unwrap()), 1001);
    assert_eq!(v.read(original_counter, 8).unwrap(), 99u64.to_le_bytes());
    assert!(unrelated.flags(fd).is_err());
}
#[test]
fn memfd_source_solo_import_and_allocation_errors_share_original_ordering() {
    let mut linux = Linux::new(0x100000);
    linux.vfs.set_descriptor_limit(3);
    let mut memory = Memory::default();
    memory.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
    let target = t();
    let (send, receive) = std::sync::mpsc::channel();
    let direct = DirectSyscalls::default()
        .with_paths(linux.vfs.path_queries())
        .with_file_executor(Arc::new(Queue(send)));
    for (address, flags, name, expected) in [
        (0x9000, 4, Vec::new(), 14),
        (0x1000, 4, b"valid\0".to_vec(), 22),
        (0x1000, 0, [vec![b'x'; 250], vec![0]].concat(), 22),
        (0x1000, 0, vec![b'x'; 4096], 36),
        (0x1000, 0, b"valid\0".to_vec(), 24),
    ] {
        if !name.is_empty() {
            memory.write(0x1000, &name).unwrap();
        }
        let args = [address, flags, 0, 0, 0, 0];
        assert_eq!(
            linux.syscall(
                279,
                args,
                &mut memory,
                &mut crate::CapturedOutput::default()
            ),
            Err(Errno(expected))
        );
        let attempt = direct
            .start_file_call(279, args, &mut memory, 1, &Arc::downgrade(&target))
            .unwrap();
        let attempt = match attempt {
            IoAttempt::Blocked(wait) => {
                let pending = wait.file_pending().unwrap();
                let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
                result.complete(work.run());
                drop(wait);
                DirectSyscalls::default().start_retained_file(
                    pending,
                    279,
                    args,
                    &mut memory,
                    1,
                    &Arc::downgrade(&target),
                )
            }
            value => value,
        };
        assert!(matches!(attempt,IoAttempt::Complete(Err(Errno(e))) if e==expected));
        assert!(receive.try_recv().is_err());
    }
    assert!(DirectSyscalls::default()
        .start_file_call(279, [0; 6], &mut memory, 1, &Arc::downgrade(&target))
        .is_none());
}
#[test]
fn mapped_write_seal_parks_and_keeps_its_original_inode_through_close_and_fd_reuse() {
    for cancel in [false, true] {
        let mut v = trames_vfs::Vfs::default();
        let fd = v.memfd_create(b"original", 2).unwrap();
        v.write(fd, b"original bytes").unwrap();
        let alias = v.dup(fd, 0, false).unwrap();
        // A private read-only mapping keeps backing without VM_MAYWRITE.
        // Shared mappings of O_RDWR prevent WRITE seals even while read-only.
        let pages = v.mapping_pages(fd, 0, PAGE_SIZE, false, false).unwrap();
        let mut memory = Memory::default();
        memory
            .map_backed(0x10000, pages, false, Permissions::R, false)
            .unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let target = t();
        let direct = DirectSyscalls::default()
            .with_resources(v.descriptor_factory())
            .with_paths(v.path_queries())
            .with_file_executor(Arc::new(Queue(send)));
        let args = [fd as u64, 1033, 8, 0, 0, 0];
        let Some(IoAttempt::Blocked(wait)) =
            direct.start_file_call(25, args, &mut memory, 1, &Arc::downgrade(&target))
        else {
            panic!("native seal sync must release its execution slot")
        };
        let pending = wait.file_pending().unwrap();
        drop(wait);
        v.close(fd).unwrap();
        assert_eq!(v.memfd_create(b"replacement", 2).unwrap(), fd);
        drop(direct);
        let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
        if cancel {
            drop(pending);
        } else {
            std::thread::spawn(move || result.complete(work.run()))
                .join()
                .unwrap();
            assert!(matches!(
                DirectSyscalls::default().start_retained_file(
                    pending,
                    25,
                    args,
                    &mut memory,
                    1,
                    &Arc::downgrade(&target)
                ),
                IoAttempt::Complete(Ok(0))
            ));
            assert_eq!(v.seals(alias, None), Ok(8));
            assert_eq!(v.pwrite(alias, b"changed", 0), Err(Errno(1)));
            assert_eq!(v.pread(alias, 32, 0).unwrap(), b"original bytes");
            assert_eq!(v.seals(fd, None), Ok(0));
            continue;
        }
        // Once accepted by the existing disk pool, cancellation may leave
        // the real inode effect, but must never redirect it to a reused FD.
        result.complete(work.run());
        assert_eq!(v.seals(alias, None), Ok(8));
        assert_eq!(v.seals(fd, None), Ok(0));
    }
}
#[test]
fn mmap_plan_waits_before_page_preparation_and_retains_original_fd() {
    let mut linux = Linux::new(0x100000);
    linux
        .vfs
        .import_file(b"/original", b"original bytes".to_vec())
        .unwrap();
    linux
        .vfs
        .import_file(b"/other", b"replacement".to_vec())
        .unwrap();
    let fd = linux.vfs.open_at(-100, b"/original", 2, 0).unwrap();
    let mut memory = Memory::default();
    let args = [0x4000, PAGE_SIZE, 3, 0x12, fd as u64, 0];
    let mut plan = linux.prepare_mmap(args, &memory).unwrap();
    let layout = plan.layout().unwrap().clone();
    let exclusive = layout.write().try_enter().ok().unwrap();
    assert!(!plan.try_admit(memory.memory_report()));
    assert!(memory.is_free(0x4000, PAGE_SIZE));
    linux.vfs.close(fd).unwrap();
    assert_eq!(linux.vfs.open_at(-100, b"/other", 2, 0).unwrap(), fd);
    drop(exclusive);
    assert!(plan.try_admit(memory.memory_report()));
    let writer = layout.write();
    assert!(
        !writer.ready(),
        "admitted page preparation owns its backing"
    );
    assert_eq!(linux.apply_mmap(plan, &mut memory), Ok(0x4000));
    assert!(writer.ready());
    assert!(
        memory.parallel_view(&mut Default::default()).is_none(),
        "a writer accepted after mmap admission excludes CPU publication"
    );
    drop(writer);
    let view = memory.parallel_view(&mut Default::default()).unwrap();
    assert_eq!(view.read_array::<14>(0x4000).unwrap(), *b"original bytes");
    assert_eq!(linux.vfs.pread(fd, 32, 0).unwrap(), b"replacement");
}
#[test]
fn mapped_file_layout_keeps_the_original_call_through_driver_replacement_and_fd_reuse() {
    for replace in [false, true] {
        let mut v = trames_vfs::Vfs::default();
        v.import_file(b"/original", vec![0xa5; PAGE_SIZE as usize])
            .unwrap();
        v.import_file(b"/other", b"untouched".to_vec()).unwrap();
        let fd = v.open_at(-100, b"/original", 2, 0).unwrap();
        let mut memory = Memory::default();
        memory
            .map_backed(
                0x1000,
                v.mapping_pages(fd, 0, PAGE_SIZE, true, true).unwrap(),
                true,
                Permissions::RW,
                false,
            )
            .unwrap();
        let mut registry = trames_memory::parallel::Registry::default();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.write_array(0x1000, [0x42]).unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let disk: Arc<dyn FileExecutor> = Arc::new(Queue(send));
        let layouts = crate::FileLayouts::new(disk.clone());
        let target = t();
        let owner_signal = IoSignal::new(0, Arc::downgrade(&target));
        layouts.bind_owner(owner_signal.clone());
        let first_signal = IoSignal::new(0, Arc::downgrade(&target));
        let first = layouts.bind_reader(first_signal.clone());
        let mut epoch = trames_vfs::FileEpoch::default();
        let direct = DirectSyscalls::default()
            .with_files(epoch.capture(&v, true))
            .with_membership(v.shared_files())
            .with_paths(v.path_queries())
            .with_file_executor(disk)
            .with_file_layouts(layouts.clone());
        let args = [fd as u64, 1, 0, 0, 0, 0];
        let Some(IoAttempt::Blocked(wait)) =
            direct.start_file_call(46, args, &mut view, 1, &Arc::downgrade(&target))
        else {
            panic!("file layout must park directly, with no owner checkpoint");
        };
        let pending = wait.file_pending().unwrap();
        drop(wait);
        let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
        result.complete(work.run());
        let IoAttempt::Blocked(wait) =
            direct.start_retained_file(pending, 46, args, &mut view, 1, &Arc::downgrade(&target))
        else {
            panic!("accepted layout parks on original backing");
        };
        let pending = wait.file_pending().unwrap();
        drop((wait, direct));
        assert!(layouts.pending());
        let request = first.take_ready().pop().unwrap();
        let layout = request.layout().clone();
        let request = layouts.try_submit(request).err().unwrap();
        // Publish a resource wake before parking: it must survive the transfer.
        request.signal.notify();
        layouts.restore(request);
        let request = first.take_ready().pop().unwrap();
        layouts.restore(request);
        assert!(
            first.take_ready().is_empty(),
            "no polling while Views remain"
        );
        v.close(fd).unwrap();
        assert_eq!(v.open_at(-100, b"/other", 2, 0).unwrap(), fd);
        let replacement_signal = IoSignal::new(0, Arc::downgrade(&target));
        let replacement = replace.then(|| layouts.bind_reader(replacement_signal.clone()));
        drop(first);
        drop(view);
        memory.commit_parallel().unwrap();
        let request = if let Some(replacement) = &replacement {
            assert!(replacement_signal.ready());
            assert!(
                !owner_signal.ready(),
                "replaced source remains the only reader"
            );
            assert!(layouts.take_owner().is_empty());
            replacement.take_ready().pop().unwrap()
        } else {
            assert!(owner_signal.ready());
            layouts.take_owner().pop().unwrap()
        };
        assert!(layouts.try_submit(request).is_ok());
        assert!(!layouts.pending());
        let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            layout.pending(),
            "native executor still owns publication exclusion"
        );
        assert!(memory.parallel_view(&mut registry).is_none());
        result.complete(work.run());
        assert!(!layout.pending());
        let direct = DirectSyscalls::default();
        assert!(matches!(
            direct.start_retained_file(pending, 46, args, &mut memory, 1, &Arc::downgrade(&target)),
            IoAttempt::Complete(Ok(0))
        ));
        let original = v.open_at(-100, b"/original", 0, 0).unwrap();
        assert_eq!(v.read(original, 32).unwrap(), [0x42]);
        assert_eq!(v.pread(fd, 32, 0).unwrap(), b"untouched");
        assert!(
            receive.try_recv().is_err(),
            "accepted mutation executes exactly once"
        );
        epoch.finish();
    }
}
fn disk() -> (std::path::PathBuf, trames_vfs::Vfs) {
    let path = std::env::temp_dir().join(format!(
        "trames-accepted-file-{}-{}",
        std::process::id(),
        trames_memory::new_backing_identity()
    ));
    let v = trames_vfs::Vfs::open_disk(&path, Default::default()).unwrap();
    (path, v)
}
#[test]
fn imported_write_survives_epoch_drop_input_changes_fd_reuse_and_native_completion() {
    let (path, mut v) = disk();
    v.import_file(b"/old", Vec::new()).unwrap();
    v.import_file(b"/other", b"untouched".to_vec()).unwrap();
    let fd = v.open_at(-100, b"/old", 2, 0).unwrap();
    let mut memory = Memory::default();
    memory.map(0x10000, 8 * PAGE_SIZE, Permissions::RW).unwrap();
    memory.write(0x10000, &vec![0xa5; 32768]).unwrap();
    let mut epoch = trames_vfs::FileEpoch::default();
    let caps = epoch.capture(&v, true);
    let (send, receive) = std::sync::mpsc::channel();
    let old_target = t();
    let direct = DirectSyscalls::default()
        .with_files(caps)
        .with_membership(v.shared_files())
        .with_paths(v.path_queries())
        .with_file_executor(Arc::new(Queue(send)));
    let args = [fd as u64, 0x10000, 32768, 0, 0, 0];
    let Some(IoAttempt::Blocked(wait)) =
        direct.start_file_call(64, args, &mut memory, 1, &Arc::downgrade(&old_target))
    else {
        panic!("native write should release its CPU slot");
    };
    assert!(
        wait.notification_external(),
        "disk completion must wake joined execution"
    );
    let pending = wait.file_pending().unwrap();
    drop(wait);
    drop((direct, old_target));
    epoch.finish();
    memory.write(0x10000, &vec![0x33; 32768]).unwrap();
    v.close(fd).unwrap();
    assert_eq!(v.open_at(-100, b"/other", 2, 0).unwrap(), fd);
    let new_target = t();
    let direct = DirectSyscalls::default();
    let IoAttempt::Blocked(wait) = direct.start_retained_file(
        pending,
        64,
        args,
        &mut memory,
        1,
        &Arc::downgrade(&new_target),
    ) else {
        panic!("original native result is not ready");
    };
    let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    std::thread::spawn(move || result.complete(work.run()))
        .join()
        .unwrap();
    assert!(wait.signal.ready());
    let pending = wait.file_pending().unwrap();
    drop(wait);
    assert!(matches!(
        direct.start_retained_file(
            pending,
            64,
            args,
            &mut memory,
            1,
            &Arc::downgrade(&new_target)
        ),
        IoAttempt::Complete(Ok(32768))
    ));
    let original = v.open_at(-100, b"/old", 0, 0).unwrap();
    assert_eq!(v.read(original, 32768).unwrap(), vec![0xa5; 32768]);
    assert_eq!(v.pread(fd, 32, 0).unwrap(), b"untouched");
    drop((direct, v));
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn first_destination_fault_leaves_disk_read_unsubmitted_and_offset_unchanged() {
    let (path, mut v) = disk();
    v.import_file(b"/data", vec![0xa5; 32768]).unwrap();
    let fd = v.open_at(-100, b"/data", 2, 0).unwrap();
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    for (a, n) in [
        (0x10000, 0x20000u64),
        (0x10008, 2),
        (0x10010, 0x10100),
        (0x10018, 2),
    ] {
        memory.write_array(a, n.to_le_bytes()).unwrap();
    }
    let mut epoch = trames_vfs::FileEpoch::default();
    let caps = epoch.capture(&v, true);
    let (send, receive) = std::sync::mpsc::channel();
    let direct = DirectSyscalls::default()
        .with_files(caps)
        .with_membership(v.shared_files())
        .with_paths(v.path_queries())
        .with_file_executor(Arc::new(Queue(send)));
    assert!(matches!(
        direct.start_file_call(
            65,
            [fd as u64, 0x10000, 2, 0, 0, 0],
            &mut memory,
            1,
            &Arc::downgrade(&t())
        ),
        Some(IoAttempt::Complete(Err(Errno(14))))
    ));
    assert!(receive.try_recv().is_err());
    assert_eq!(v.seek(fd, 0, 1), Ok(0));
    drop((direct, v));
    epoch.finish();
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn finite_file_limit_returns_partial_progress_then_one_original_signal_boundary() {
    let mut v = trames_vfs::Vfs::default();
    v.import_file(b"/data", Vec::new()).unwrap();
    let fd = v.open_at(-100, b"/data", 2, 0).unwrap();
    v.set_file_size_limit(4);
    let mut epoch = trames_vfs::FileEpoch::default();
    let caps = epoch.capture(&v, false);
    let direct = DirectSyscalls::default()
        .with_files(caps)
        .with_membership(v.shared_files())
        .with_paths(v.path_queries());
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.write(0x10000, b"12345678").unwrap();
    let args = [fd as u64, 0x10000, 8, 0, 0, 0];
    let target = t();
    assert!(matches!(
        direct.start_file_call(64, args, &mut memory, 1, &Arc::downgrade(&target)),
        Some(IoAttempt::Complete(Ok(4)))
    ));
    let Some(IoAttempt::FileCheckpoint(checkpoint)) =
        direct.start_file_call(64, args, &mut memory, 1, &Arc::downgrade(&target))
    else {
        panic!("SIGXFSZ task transition");
    };
    assert!(matches!(
        checkpoint.take(),
        FileBoundary::Signal {
            value: Err(Errno(27))
        }
    ));
    assert_eq!(v.pread(fd, 32, 0).unwrap(), b"1234");
    assert!(!v.take_file_size_signal());
    epoch.finish();
}
#[test]
fn source_file_copy_preserves_explicit_offsets_and_implicit_cursors() {
    let mut v = trames_vfs::Vfs::default();
    v.import_file(b"/source", b"abcdef".to_vec()).unwrap();
    v.import_file(b"/target", Vec::new()).unwrap();
    let a = v.open_at(-100, b"/source", 2, 0).unwrap();
    let b = v.open_at(-100, b"/target", 2, 0).unwrap();
    let mut epoch = trames_vfs::FileEpoch::default();
    let caps = epoch.capture(&v, true);
    let (send, receive) = std::sync::mpsc::channel();
    let direct = DirectSyscalls::default()
        .with_files(caps)
        .with_membership(v.shared_files())
        .with_paths(v.path_queries())
        .with_file_executor(Arc::new(Queue(send)));
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.write_array(0x10000, 1u64.to_le_bytes()).unwrap();
    memory.write_array(0x10008, 2u64.to_le_bytes()).unwrap();
    let args = [a as u64, 0x10000, b as u64, 0x10008, 3, 0];
    let target = t();
    let Some(IoAttempt::Blocked(wait)) =
        direct.start_file_call(285, args, &mut memory, 1, &Arc::downgrade(&target))
    else {
        panic!("accepted file copy");
    };
    let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    result.complete(work.run());
    let pending = wait.file_pending().unwrap();
    drop(wait);
    assert!(matches!(
        direct.start_retained_file(pending, 285, args, &mut memory, 1, &Arc::downgrade(&target)),
        IoAttempt::Complete(Ok(3))
    ));
    assert_eq!(memory.read_u64(0x10000).unwrap(), 4);
    assert_eq!(memory.read_u64(0x10008).unwrap(), 5);
    assert_eq!(v.pread(b, 32, 0).unwrap(), b"\0\0bcd");
    assert_eq!(v.seek(a, 0, 1).unwrap(), 0);
    assert_eq!(v.seek(b, 0, 1).unwrap(), 0);
    epoch.finish();
}

#[test]
fn pathname_truncate_retains_the_resolved_file_and_imported_path_through_native_wait() {
    let (directory, mut v) = disk();
    v.import_file(b"/file", b"original".to_vec()).unwrap();
    let fd = v.open_at(-100, b"/file", 2, 0).unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let direct = DirectSyscalls::default()
        .with_paths(v.path_queries())
        .with_file_executor(Arc::new(Queue(send)));
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.write(0x10000, b"/file\0").unwrap();
    let args = [0x10000, 3, 0, 0, 0, 0];
    let target = t();
    let Some(IoAttempt::Blocked(wait)) =
        direct.start_file_call(45, args, &mut memory, 1, &Arc::downgrade(&target))
    else {
        panic!("accepted pathname truncate");
    };
    memory.write(0x10000, b"/other\0").unwrap();
    v.rename_at(-100, b"/file", -100, b"/old", 0).unwrap();
    v.import_file(b"/file", b"replacement".to_vec()).unwrap();
    let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    result.complete(work.run());
    let pending = wait.file_pending().unwrap();
    drop(wait);
    assert!(matches!(
        direct.start_retained_file(pending, 45, args, &mut memory, 1, &Arc::downgrade(&target)),
        IoAttempt::Complete(Ok(0))
    ));
    assert_eq!(v.pread(fd, 32, 0).unwrap(), b"ori");
    let replacement = v.open_at(-100, b"/file", 0, 0).unwrap();
    assert_eq!(replacement, fd + 1);
    assert_eq!(v.read(replacement, 32).unwrap(), b"replacement");
    drop((direct, v));
    std::fs::remove_dir_all(directory).unwrap();
}
#[test]
fn namespace_call_retains_original_path_and_dirfd_across_native_wait_and_reuse() {
    let (path, mut v) = disk();
    v.mkdir_at(-100, b"/old", 0o755).unwrap();
    v.mkdir_at(-100, b"/other", 0o755).unwrap();
    let fd = v.open_at(-100, b"/old", 0, 0).unwrap();
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.write(0x10000, b"child\0").unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let direct = DirectSyscalls::default()
        .with_paths(v.path_queries())
        .with_file_executor(Arc::new(Queue(send)));
    let target = t();
    let args = [fd as u64, 0x10000, 0o700, 0, 0, 0];
    let Some(IoAttempt::Blocked(wait)) =
        direct.start_file_call(34, args, &mut memory, 1, &Arc::downgrade(&target))
    else {
        panic!("persistent namespace work must release the execution slot")
    };
    let pending = wait.file_pending().unwrap();
    drop((wait, direct));
    memory.write(0x10000, b"other\0").unwrap();
    v.close(fd).unwrap();
    assert_eq!(v.open_at(-100, b"/other", 0, 0).unwrap(), fd);
    let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    std::thread::spawn(move || result.complete(work.run()))
        .join()
        .unwrap();
    assert!(matches!(
        DirectSyscalls::default().start_retained_file(
            pending,
            34,
            args,
            &mut memory,
            1,
            &Arc::downgrade(&target)
        ),
        IoAttempt::Complete(Ok(0))
    ));
    assert!(v.stat_at(-100, b"/old/child").is_ok());
    assert_eq!(v.stat_at(-100, b"/other/other"), Err(Errno(2)));
    drop(v);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn stream_wait_rearms_original_fds_and_copies_offsets_only_on_commit() {
    let mut v = trames_vfs::Vfs::default();
    v.import_file(b"/input", b"payload".to_vec()).unwrap();
    let source = v.open_at(-100, b"/input", 0, 0).unwrap();
    let [read, write] = v.pipe(0).unwrap();
    v.write(write, &vec![1; 65536]).unwrap();
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.write_array(0x10000, 1u64.to_le_bytes()).unwrap();
    let direct = DirectSyscalls::default()
        .with_membership(v.shared_files())
        .with_paths(v.path_queries());
    let target = t();
    let args = [write as u64, source as u64, 0x10000, 3, 0, 0];
    let Some(IoAttempt::Blocked(wait)) =
        direct.start_file_call(71, args, &mut memory, 1, &Arc::downgrade(&target))
    else {
        panic!("full destination")
    };
    let pending = wait.file_pending().unwrap();
    assert!(pending.interruptible());
    assert_eq!(memory.read_u64(0x10000).unwrap(), 1);
    v.close(source).unwrap();
    v.import_file(b"/other", b"wrong".to_vec()).unwrap();
    assert_eq!(v.open_at(-100, b"/other", 0, 0).unwrap(), source);
    drop((wait, direct));
    v.read(read, 65536).unwrap();
    let direct = DirectSyscalls::default();
    assert!(matches!(
        direct.start_retained_file(pending, 71, args, &mut memory, 1, &Arc::downgrade(&target)),
        IoAttempt::Complete(Ok(3))
    ));
    assert_eq!(memory.read_u64(0x10000).unwrap(), 4);
    assert_eq!(v.read(read, 3).unwrap(), b"ayl");
}

#[derive(Default)]
struct FileSignal(std::sync::atomic::AtomicUsize);
impl trames_vfs::TaskSignal for FileSignal {
    fn raise(&self, signal: u32) {
        assert_eq!(signal, 25);
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
#[test]
fn size_failure_notifies_the_source_without_inline_or_native_owner_checkpoint() {
    for native in [false, true] {
        let (directory, mut v) = if native {
            let (p, v) = disk();
            (Some(p), v)
        } else {
            (None, trames_vfs::Vfs::default())
        };
        v.import_file(b"/limited", Vec::new()).unwrap();
        let fd = v.open_at(-100, b"/limited", 2, 0).unwrap();
        v.set_file_size_limit(0);
        let mut epoch = trames_vfs::FileEpoch::default();
        let files = epoch.capture(&v, true);
        let signal = Arc::new(FileSignal::default());
        let (send, receive) = std::sync::mpsc::channel();
        let direct = DirectSyscalls::default()
            .with_files(files)
            .with_membership(v.shared_files())
            .with_paths(v.path_queries())
            .with_task_signal(signal.clone())
            .with_file_executor(Arc::new(Queue(send)));
        let mut m = Memory::default();
        m.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x10000, b"x").unwrap();
        let args = [fd as u64, 0x10000, 1, 0, 0, 0];
        let wake = t();
        let result = direct
            .start_file_call(64, args, &mut m, 1, &Arc::downgrade(&wake))
            .unwrap();
        let result = if native {
            let IoAttempt::Blocked(wait) = result else {
                panic!("native operation should park only its source")
            };
            let pending = wait.file_pending().unwrap();
            drop(wait);
            let (work, completion) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
            completion.complete(work.run());
            direct.start_retained_file(pending, 64, args, &mut m, 1, &Arc::downgrade(&wake))
        } else {
            result
        };
        assert!(matches!(result, IoAttempt::Complete(Err(Errno(27)))));
        assert_eq!(signal.0.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(v.pread(fd, 8, 0).unwrap(), b"");
        drop((direct, v));
        epoch.finish();
        if let Some(p) = directory {
            std::fs::remove_dir_all(p).unwrap();
        }
    }
}

#[test]
fn source_fd_errors_preserve_canonical_abi_precedence_without_owner_work() {
    let mut linux = Linux::new(0x100000);
    linux
        .vfs
        .import_file(b"/input", b"unchanged".to_vec())
        .unwrap();
    let file = linux.vfs.open_at(-100, b"/input", 2, 0).unwrap() as u64;
    let directory = linux.vfs.open_at(-100, b"/", 0, 0).unwrap() as u64;
    let pipe = linux.vfs.pipe(0).unwrap().map(u64::from);
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    let direct = DirectSyscalls::new(linux.vfs.direct_descriptors())
        .with_paths(linux.vfs.path_queries())
        .with_resources(linux.vfs.descriptor_factory());
    let bad = u32::MAX as u64;
    let target = t();
    let mut calls = Vec::new();
    for fd in [bad, 1234] {
        for number in [46, 47, 67, 68, 69, 70, 82, 83, 267, 286, 287] {
            for operands in [
                [fd, 0x1000, 0, 0, 0, 0],
                [fd, u64::MAX, u64::MAX, u64::MAX, 0, 0],
            ] {
                calls.push((number, operands));
            }
        }
        for flags in [0, 1, 6, u64::MAX] {
            calls.push((286, [fd, u64::MAX, u64::MAX, 0, 0, flags]));
            calls.push((287, [fd, 0x1000, 0, u64::MAX, 0, flags]));
        }
        for (offset, length) in [(0, 0), (0, 1), (u64::MAX, 1), (i64::MAX as u64, 1)] {
            calls.push((47, [fd, u64::MAX, offset, length, 0, 0]));
        }
        for peer in [bad, file, directory, pipe[0], pipe[1]] {
            for pointer in [0, 0x1000, u64::MAX] {
                for flags in [0, 16, 1u64 << 40] {
                    calls.push((71, [peer, fd, pointer, 3, 0, 0]));
                    calls.push((71, [fd, peer, pointer, 3, 0, 0]));
                    calls.push((76, [fd, pointer, peer, pointer, 3, flags]));
                    calls.push((76, [peer, pointer, fd, pointer, 3, flags]));
                    calls.push((285, [fd, pointer, peer, pointer, 3, flags]));
                    calls.push((285, [peer, pointer, fd, pointer, 3, flags]));
                }
            }
        }
    }
    for fd in [directory, linux.vfs.epoll_create(0).unwrap() as u64] {
        for number in [63, 64, 65, 66, 67, 68, 69, 70, 286, 287] {
            calls.push((number, [fd, 0x1000, 0, 0, 0, 0]));
            if matches!(number, 286 | 287) {
                calls.push((number, [fd, 0x1000, 0, u64::MAX, 0, 0]));
            }
        }
    }
    for (number, args) in calls {
        let expected = linux.syscall(
            number,
            args,
            &mut memory,
            &mut crate::CapturedOutput::default(),
        );
        let attempt = direct.start_file_call(
            number as u32,
            args,
            &mut memory,
            1,
            &Arc::downgrade(&target),
        );
        assert!(
            matches!(attempt, Some(IoAttempt::Complete(value)) if value == expected),
            "source {number} {args:?}: {expected:?}"
        );
        let attempt = direct.start_owned_file(
            &mut linux.vfs,
            number as u32,
            args,
            &mut memory,
            1,
            &Arc::downgrade(&target),
        );
        assert!(
            matches!(attempt, Some(IoAttempt::Complete(value)) if value == expected),
            "owned {number} {args:?}: {expected:?}"
        );
    }
    assert_eq!(linux.vfs.pread(file as u32, 9, 0).unwrap(), b"unchanged");
    assert_eq!(linux.vfs.seek(file as u32, 0, 1), Ok(0));
    assert_eq!(memory.read_u64(0x1000), Ok(0));
}

#[test]
fn current_position_v2_pipe_wait_retains_original_fd_and_sync_error_follows_write() {
    let mut v = trames_vfs::Vfs::default();
    let [read, write] = v.pipe(0).unwrap();
    let alias = v.dup(read, 0, false).unwrap();
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.write_array(0x1000, 0x1100u64.to_le_bytes()).unwrap();
    memory.write_array(0x1008, 4u64.to_le_bytes()).unwrap();
    memory.write(0x1100, b"data").unwrap();
    let direct = DirectSyscalls::new(v.direct_descriptors()).with_paths(v.path_queries());
    let target = t();
    let args = [read as u64, 0x1000, 1, u64::MAX, 0, 0];
    let Some(IoAttempt::Blocked(wait)) =
        direct.start_file_call(286, args, &mut memory, 1, &Arc::downgrade(&target))
    else {
        panic!("a real pipe wait must return its execution slot")
    };
    v.close(read).unwrap();
    assert_eq!(v.eventfd(99, 0).unwrap(), read);
    v.write(write, b"old!").unwrap();
    assert!(wait.signal.ready());
    assert!(matches!(
        direct.resume(wait, &mut memory),
        IoAttempt::Complete(Ok(4))
    ));
    assert_eq!(memory.read_array::<4>(0x1100).unwrap(), *b"old!");
    assert_eq!(v.read(read, 8).unwrap(), 99u64.to_le_bytes());
    let args = [write as u64, 0x1000, 1, u64::MAX, 0, 2];
    assert!(matches!(
        direct.start_file_call(287, args, &mut memory, 1, &Arc::downgrade(&target)),
        Some(IoAttempt::Complete(Err(Errno(22))))
    ));
    assert_eq!(v.read(alias, 4).unwrap(), b"old!");
}

#[test]
fn fd_control_and_epoll_errors_complete_after_their_original_parameter_preludes() {
    let mut v = trames_vfs::Vfs::default();
    let event = v.eventfd(1, 0).unwrap();
    let timer = v.timerfd(1, 0).unwrap();
    let notify = v.inotify_init(0).unwrap();
    v.import_file(b"/watched", vec![]).unwrap();
    let wd = v.inotify_add(notify, b"/watched", 2).unwrap();
    let epoll = v.epoll_create(0).unwrap();
    v.epoll_ctl(epoll, 1, event, 1, 55).unwrap();
    let direct = DirectSyscalls::new(v.direct_descriptors()).with_paths(v.path_queries());
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    let target = t();
    for number in [28, 86, 87] {
        for (fd, expected) in [(u32::MAX, 9), (event, 22)] {
            // timerfd_settime copies the new itimerspec before fdget; gettime
            // and inotify_rm_watch accept the original descriptor first.
            let expected = if number == 86 { 14 } else { expected };
            let args = [fd as u64, u64::MAX, u64::MAX, u64::MAX, 0, 0];
            assert!(direct.supports_call(number, args));
            assert_eq!(
                direct.invoke(number, args, &mut memory),
                Some(Err(Errno(expected)))
            );
            assert!(
                matches!(direct.start(number, args, &mut memory, 1, &Arc::downgrade(&target), None), Some(IoAttempt::Complete(Err(Errno(error)))) if error == expected)
            );
        }
    }
    for number in [86, 87] {
        let args = [timer as u64, u64::MAX, u64::MAX, u64::MAX, 0, 0];
        let expected = crate::timerfd_control_with_boot(
            &v.timerfd_resource(timer).unwrap(),
            number,
            args,
            &mut memory,
            Instant::now(),
            None,
        );
        assert!(expected.is_err());
        assert_eq!(direct.invoke(number, args, &mut memory), Some(expected));
    }
    assert_eq!(
        direct.invoke(28, [notify as u64, wd as u64, 0, 0, 0, 0], &mut memory),
        Some(Ok(0))
    );
    assert_eq!(v.inotify_remove(notify, wd), Err(Errno(22)));
    for number in [22, 441] {
        for (args, expected) in [
            ([u32::MAX as u64, 0x1000, 1, 0, 0, 0], 9),
            ([event as u64, 0x1000, 1, 0, 0, 0], 22),
            ([u32::MAX as u64, 0x9000, 1, 0, 0, 0], 9),
            (
                [u32::MAX as u64, trames_memory::ADDRESS_LIMIT, 1, 0, 0, 0],
                14,
            ),
            ([u32::MAX as u64, 0x1000, 0, 0, 0, 0], 22),
            ([u32::MAX as u64, 0x1000, 1, 0, 0x1200, 7], 22),
        ] {
            assert!(direct.supports_call(number, args));
            assert!(
                matches!(direct.start(number, args, &mut memory, 1, &Arc::downgrade(&target), None), Some(IoAttempt::Complete(Err(Errno(error)))) if error == expected),
                "epoll {number} {args:?}"
            );
        }
    }
    let wait = crate::RetainedWait::prepare_worker(
        &direct.descriptors(),
        &memory,
        22,
        [epoll as u64, 0x1000, 1, 0, 0, 0],
        None,
    )
    .unwrap()
    .unwrap();
    v.close(epoll).unwrap();
    assert_eq!(v.eventfd(7, 0).unwrap(), epoll);
    assert_eq!(wait.check(&mut memory), Ok(1));
    assert_eq!(memory.read_u64(0x1008), Ok(55));
    assert_eq!(v.read(epoll, 8).unwrap(), 7u64.to_le_bytes());
}
