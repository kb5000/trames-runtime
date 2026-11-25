// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};
type Host = (
    Box<dyn crate::HostFileTask>,
    Option<crate::HostFileAdmission>,
);
#[derive(Default)]
struct Queue {
    files: Mutex<Vec<(trames_vfs::FileWork, Arc<FileResult>)>>,
    host: Mutex<Vec<Host>>,
}
impl FileExecutor for Queue {
    fn submit_file(&self, work: trames_vfs::FileWork, result: Arc<FileResult>) {
        result.begin();
        self.files.lock().unwrap().push((work, result));
    }
    fn submit_host(
        &self,
        work: Box<dyn crate::HostFileTask>,
        admission: Option<crate::HostFileAdmission>,
    ) {
        self.host.lock().unwrap().push((work, admission));
    }
}
impl Queue {
    fn file(&self) {
        let (work, result) = self.files.lock().unwrap().remove(0);
        result.complete(work.run());
    }
    fn host(&self) {
        let (work, admission) = self.host.lock().unwrap().remove(0);
        work.run(admission);
    }
}
struct Wake;
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn value(attempt: IoAttempt) -> Result<u64, Errno> {
    let IoAttempt::Complete(result) = attempt else {
        panic!("original io_submit must complete");
    };
    result
}
fn fixture() -> (
    trames_vfs::Vfs,
    Aio,
    DirectSyscalls,
    Memory,
    Arc<Queue>,
    Arc<dyn IoWake>,
    u64,
) {
    let vfs = trames_vfs::Vfs::default();
    let aio = Aio::default();
    let queue = Arc::new(Queue::default());
    let source = DirectSyscalls::new(vfs.direct_descriptors())
        .with_aio(aio.clone(), vfs.native_events())
        .with_paths(vfs.path_queries())
        .with_file_executor(queue.clone())
        .with_file_layouts(crate::FileLayouts::new(queue.clone()));
    let mut memory = Memory::default();
    memory.map(0x1000, 0x9000, Permissions::RW).unwrap();
    aio.setup([8, 0x1000, 0, 0, 0, 0], &mut memory).unwrap();
    let id = memory.read_u64(0x1000).unwrap();
    (vfs, aio, source, memory, queue, Arc::new(Wake), id)
}
fn iocb(fd: u32, op: u16, address: u64, count: u64, event: Option<u32>) -> [u8; 64] {
    let mut cb = [0; 64];
    cb[..8].copy_from_slice(&123u64.to_le_bytes());
    cb[16..18].copy_from_slice(&op.to_le_bytes());
    cb[20..24].copy_from_slice(&fd.to_le_bytes());
    cb[24..32].copy_from_slice(&address.to_le_bytes());
    cb[32..40].copy_from_slice(&count.to_le_bytes());
    if let Some(event) = event {
        cb[56..60].copy_from_slice(&1u32.to_le_bytes());
        cb[60..64].copy_from_slice(&event.to_le_bytes());
    }
    cb
}
#[test]
fn buffered_predecessor_can_supply_the_next_iocb_header_or_pointer_before_it_is_imported() {
    for pointer in [false, true] {
        let (mut vfs, aio, source, mut memory, queue, wake, id) = fixture();
        let target = Arc::downgrade(&wake);
        vfs.import_file(b"/destination", Vec::new()).unwrap();
        let destination = vfs.open_at(-100, b"/destination", 2, 0).unwrap();
        let next = iocb(destination, 1, 0x3000, 7, None);
        memory.write(0x3000, b"payload").unwrap();
        vfs.import_file(
            b"/input",
            if pointer {
                0x2080u64.to_le_bytes().to_vec()
            } else {
                next.to_vec()
            },
        )
        .unwrap();
        let input = vfs.open_at(-100, b"/input", 0, 0).unwrap();
        memory
            .write_array(
                0x2000,
                iocb(
                    input,
                    0,
                    if pointer { 0x1808 } else { 0x2080 },
                    if pointer { 8 } else { 64 },
                    None,
                ),
            )
            .unwrap();
        memory
            .write_array(
                0x2080,
                if pointer {
                    next
                } else {
                    iocb(u32::MAX, 1, 0x3000, 7, None)
                },
            )
            .unwrap();
        memory.write_array(0x1800, 0x2000u64.to_le_bytes()).unwrap();
        memory
            .write_array(
                0x1808,
                if pointer { 0xdeadbeefu64 } else { 0x2080u64 }.to_le_bytes(),
            )
            .unwrap();
        let Some(IoAttempt::Blocked(wait)) =
            source.start(2, [id, 2, 0x1800, 0, 0, 0], &mut memory, 1, &target, None)
        else {
            panic!("predecessor executes before importing the next request");
        };
        assert_eq!(queue.files.lock().unwrap().len(), 1);
        queue.file();
        let IoAttempt::Blocked(wait) = source.resume(wait, &mut memory) else {
            panic!("dependent write is now accepted");
        };
        assert_eq!(
            aio.context(id, &memory).unwrap().state.lock().unwrap().tail,
            1
        );
        assert_eq!(queue.files.lock().unwrap().len(), 1);
        queue.file();
        assert_eq!(value(source.resume(wait, &mut memory)), Ok(2));
        assert_eq!(vfs.pread(destination, 7, 0).unwrap(), b"payload");
    }
}
#[test]
fn completed_prefix_is_published_before_later_input_wait_and_survives_fatal_copy_failure() {
    let (mut vfs, aio, source, mut memory, queue, wake, id) = fixture();
    let target = Arc::downgrade(&wake);
    vfs.import_file(b"/data", b"data".to_vec()).unwrap();
    let fd = vfs.open_at(-100, b"/data", 0, 0).unwrap();
    let event = vfs.eventfd(0, 0x800).unwrap();
    memory
        .write_array(0x2000, iocb(fd, 0, 0x3000, 4, Some(event)))
        .unwrap();
    memory.write_array(0x1800, 0x2000u64.to_le_bytes()).unwrap();
    memory.write_array(0x1808, 0x6000u64.to_le_bytes()).unwrap();
    memory.unmap(0x6000, PAGE_SIZE).unwrap();
    let _page = file::copyout_tests::install(&mut memory, 0x6000);
    let Some(IoAttempt::Blocked(wait)) =
        source.start(2, [id, 2, 0x1800, 0, 0, 0], &mut memory, 1, &target, None)
    else {
        panic!("original read");
    };
    queue.file();
    let IoAttempt::Blocked(wait) = source.resume(wait, &mut memory) else {
        panic!("second header page waits");
    };
    assert_eq!(
        aio.context(id, &memory).unwrap().state.lock().unwrap().tail,
        1
    );
    assert_eq!(vfs.read(event, 8).unwrap(), 1u64.to_le_bytes());
    assert_eq!(
        value(source.drain_aio_exit(wait.aio.unwrap(), &mut memory, 1, &target)),
        Ok(1)
    );
    assert_eq!(memory.read_array::<4>(0x3000).unwrap(), *b"data");
    assert_eq!(vfs.read(event, 8), Err(Errno(11)));
    assert!(queue.files.lock().unwrap().is_empty());
}
#[test]
fn later_fd_lookup_observes_reuse_after_the_buffered_predecessor_finishes() {
    let (mut vfs, _aio, source, mut memory, queue, wake, id) = fixture();
    let target = Arc::downgrade(&wake);
    vfs.import_file(b"/input", b"old".to_vec()).unwrap();
    vfs.import_file(b"/replacement", b"new".to_vec()).unwrap();
    let fd = vfs.open_at(-100, b"/input", 0, 0).unwrap();
    for (index, address) in [(0u64, 0x3000), (1, 0x3100)] {
        memory
            .write_array(0x2000 + index * 64, iocb(fd, 0, address, 3, None))
            .unwrap();
        memory
            .write_array(0x1800 + index * 8, (0x2000 + index * 64).to_le_bytes())
            .unwrap();
    }
    let Some(IoAttempt::Blocked(wait)) =
        source.start(2, [id, 2, 0x1800, 0, 0, 0], &mut memory, 1, &target, None)
    else {
        panic!("first original read");
    };
    vfs.close(fd).unwrap();
    assert_eq!(vfs.open_at(-100, b"/replacement", 0, 0).unwrap(), fd);
    queue.file();
    let IoAttempt::Blocked(wait) = source.resume(wait, &mut memory) else {
        panic!("later reused descriptor");
    };
    queue.file();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(2));
    assert_eq!(memory.read_array::<3>(0x3000).unwrap(), *b"old");
    assert_eq!(memory.read_array::<3>(0x3100).unwrap(), *b"new");
}
#[test]
fn repeated_fsync_iocb_address_owns_separate_async_requests_and_original_eventfd() {
    let (mut vfs, aio, source, mut memory, queue, wake, id) = fixture();
    let target = Arc::downgrade(&wake);
    vfs.import_file(b"/data", Vec::new()).unwrap();
    let fd = vfs.open_at(-100, b"/data", 2, 0).unwrap();
    let event = vfs.eventfd(0, 0x800).unwrap();
    let duplicate = vfs.dup(event, 0, false).unwrap();
    memory
        .write_array(0x2000, iocb(fd, 2, 0, 0, Some(event)))
        .unwrap();
    for index in 0..2 {
        memory
            .write_array(0x1800 + index * 8, 0x2000u64.to_le_bytes())
            .unwrap();
    }
    assert_eq!(
        value(
            source
                .start(2, [id, 2, 0x1800, 0, 0, 0], &mut memory, 1, &target, None)
                .unwrap()
        ),
        Ok(2)
    );
    let context = aio.context(id, &memory).unwrap();
    assert_eq!(context.state.lock().unwrap().active.len(), 2);
    assert_eq!(queue.host.lock().unwrap().len(), 2);
    assert!(queue.files.lock().unwrap().is_empty());
    vfs.close(event).unwrap();
    assert_eq!(vfs.eventfd(0, 0x800).unwrap(), event);
    queue.host();
    queue.host();
    assert_eq!(context.state.lock().unwrap().tail, 2);
    assert!(context.state.lock().unwrap().active.is_empty());
    assert!(context.state.lock().unwrap().owned.is_empty());
    assert_eq!(vfs.read(duplicate, 8).unwrap(), 2u64.to_le_bytes());
    assert_eq!(vfs.read(event, 8), Err(Errno(11)));
}
#[test]
fn async_fsync_finishes_while_next_iocb_input_is_missing_and_destroy_keeps_original_producer() {
    let (mut vfs, aio, source, mut memory, queue, wake, id) = fixture();
    let target = Arc::downgrade(&wake);
    vfs.import_file(b"/data", Vec::new()).unwrap();
    let fd = vfs.open_at(-100, b"/data", 2, 0).unwrap();
    let event = vfs.eventfd(0, 0x800).unwrap();
    memory
        .write_array(0x2000, iocb(fd, 3, 0, 0, Some(event)))
        .unwrap();
    memory.write_array(0x1800, 0x2000u64.to_le_bytes()).unwrap();
    memory.write_array(0x1808, 0x6000u64.to_le_bytes()).unwrap();
    memory.unmap(0x6000, PAGE_SIZE).unwrap();
    let _page = file::copyout_tests::install(&mut memory, 0x6000);
    let Some(IoAttempt::Blocked(wait)) =
        source.start(2, [id, 2, 0x1800, 0, 0, 0], &mut memory, 1, &target, None)
    else {
        panic!("later input waits");
    };
    let context = aio.context(id, &memory).unwrap();
    assert_eq!(queue.host.lock().unwrap().len(), 1);
    let Some(IoAttempt::Blocked(destroy)) =
        source.start(1, [id, 0, 0, 0, 0, 0], &mut memory, 2, &target, None)
    else {
        panic!("original context still has a user and fsync");
    };
    queue.host();
    assert_eq!(context.state.lock().unwrap().tail, 1);
    assert_eq!(vfs.read(event, 8).unwrap(), 1u64.to_le_bytes());
    assert_eq!(
        value(source.drain_aio_exit(wait.aio.unwrap(), &mut memory, 1, &target)),
        Ok(1)
    );
    assert_eq!(value(source.resume(destroy, &mut memory)), Ok(0));
}
#[test]
fn missing_async_executor_hands_off_the_original_fsync_without_rereading_its_iocb() {
    let (mut vfs, aio, source, mut memory, queue, wake, id) = fixture();
    let target = Arc::downgrade(&wake);
    vfs.import_file(b"/data", Vec::new()).unwrap();
    let fd = vfs.open_at(-100, b"/data", 2, 0).unwrap();
    memory.write_array(0x2000, iocb(fd, 2, 0, 0, None)).unwrap();
    memory.write_array(0x1800, 0x2000u64.to_le_bytes()).unwrap();
    let bare = DirectSyscalls::new(vfs.direct_descriptors())
        .with_aio(aio, vfs.native_events())
        .with_paths(vfs.path_queries());
    let Some(IoAttempt::FileCheckpoint(checkpoint)) =
        bare.start(2, [id, 1, 0x1800, 0, 0, 0], &mut memory, 1, &target, None)
    else {
        panic!("original capability boundary");
    };
    memory
        .write_array(0x2000, iocb(u32::MAX, 0, 0, 0, None))
        .unwrap();
    vfs.close(fd).unwrap();
    let file::FileBoundary::Aio(call) = checkpoint.take() else {
        panic!("original AIO call");
    };
    assert_eq!(
        value(source.start_retained_aio(call, &mut memory, 1, &target)),
        Ok(1)
    );
    assert_eq!(queue.host.lock().unwrap().len(), 1);
    queue.host();
}
fn receive(vfs: &mut trames_vfs::Vfs, fd: u32, opcode: u32) -> Vec<u8> {
    let bytes = vfs.read(fd, 128 * 1024).unwrap();
    assert_eq!(&bytes[4..8], &opcode.to_le_bytes());
    bytes
}
fn reply(vfs: &mut trames_vfs::Vfs, fd: u32, request: &[u8], payload: &[u8]) {
    let mut bytes = Vec::new();
    bytes.extend(((16 + payload.len()) as u32).to_le_bytes());
    bytes.extend(0i32.to_le_bytes());
    bytes.extend(&request[8..16]);
    bytes.extend(payload);
    assert_eq!(vfs.write(fd, &bytes), Ok(bytes.len()));
}
#[test]
fn directory_fsync_waits_on_original_daemon_reply_after_submit_returns_and_fd_is_reused() {
    let (mut vfs, aio, source, mut memory, queue, wake, id) = fixture();
    let target = Arc::downgrade(&wake);
    vfs.set_runtime_info(1, Default::default());
    vfs.mkdir_at(-100, b"/mnt", 0o755).unwrap();
    let daemon = vfs.open_at(-100, b"/dev/fuse", 2, 0).unwrap();
    vfs.mount(
        None,
        b"/mnt",
        Some(b"fuse"),
        0,
        Some(format!("fd={daemon},rootmode=40755,user_id=0,group_id=0").as_bytes()),
    )
    .unwrap();
    let init = receive(&mut vfs, daemon, 26);
    let mut version = [0; 64];
    version[..4].copy_from_slice(&7u32.to_le_bytes());
    version[4..8].copy_from_slice(&34u32.to_le_bytes());
    reply(&mut vfs, daemon, &init, &version);
    // Refresh only the source's path capability after creating the mount.
    let source = source.with_paths(vfs.path_queries());
    memory.write(0x1600, b"/mnt\0").unwrap();
    let args = [
        (-100i64) as u64,
        0x1600,
        trames_vfs::O_DIRECTORY as u64,
        0,
        0,
        0,
    ];
    let open = source
        .start_file_call(56, args, &mut memory, 1, &target)
        .unwrap();
    let getattr = receive(&mut vfs, daemon, 3);
    let mut attr = [0; 104];
    attr[16..24].copy_from_slice(&1u64.to_le_bytes());
    attr[76..80].copy_from_slice(&0o40755u32.to_le_bytes());
    reply(&mut vfs, daemon, &getattr, &attr);
    let IoAttempt::Blocked(wait) = open else {
        panic!("original getattr");
    };
    let open = source.resume(wait, &mut memory);
    let opendir = receive(&mut vfs, daemon, 27);
    let mut handle = [0; 16];
    handle[..8].copy_from_slice(&123u64.to_le_bytes());
    reply(&mut vfs, daemon, &opendir, &handle);
    let IoAttempt::Blocked(wait) = open else {
        panic!("original opendir");
    };
    let fd = value(source.resume(wait, &mut memory)).unwrap() as u32;
    let event = vfs.eventfd(0, 0x800).unwrap();
    memory
        .write_array(0x2000, iocb(fd, 2, 0, 0, Some(event)))
        .unwrap();
    memory.write_array(0x1800, 0x2000u64.to_le_bytes()).unwrap();
    assert_eq!(
        value(
            source
                .start(2, [id, 1, 0x1800, 0, 0, 0], &mut memory, 1, &target, None)
                .unwrap()
        ),
        Ok(1)
    );
    drop(source);
    queue.host();
    let fsync = receive(&mut vfs, daemon, 30);
    assert_eq!(&fsync[40..48], &123u64.to_le_bytes());
    let context = aio.context(id, &memory).unwrap();
    assert_eq!(context.state.lock().unwrap().tail, 0);
    assert_eq!(vfs.read(event, 8), Err(Errno(11)));
    assert!(queue.host.lock().unwrap().is_empty());
    vfs.close(fd).unwrap();
    assert_eq!(vfs.open_at(-100, b"/replacement", 0x42, 0o600).unwrap(), fd);
    reply(&mut vfs, daemon, &fsync, &[]);
    assert_eq!(queue.host.lock().unwrap().len(), 1);
    queue.host();
    assert_eq!(context.state.lock().unwrap().tail, 1);
    assert_eq!(vfs.read(event, 8).unwrap(), 1u64.to_le_bytes());
    let release = receive(&mut vfs, daemon, 29);
    assert_eq!(&release[40..48], &123u64.to_le_bytes());
}
#[test]
fn negative_count_precedes_context_lookup_and_fsync_rejects_nonzero_data_operands() {
    let (mut vfs, _aio, source, mut memory, queue, wake, id) = fixture();
    let target = Arc::downgrade(&wake);
    assert_eq!(
        value(
            source
                .start(
                    2,
                    [0xdeadbeef, u64::MAX, 0, 0, 0, 0],
                    &mut memory,
                    1,
                    &target,
                    None
                )
                .unwrap()
        ),
        Err(Errno(22))
    );
    vfs.import_file(b"/data", Vec::new()).unwrap();
    let fd = vfs.open_at(-100, b"/data", 2, 0).unwrap();
    for (address, count, offset) in [(0x3000u64, 0u64, 0u64), (0, 1, 0), (0, 0, 1)] {
        let mut cb = iocb(fd, 2, address, count, None);
        cb[40..48].copy_from_slice(&offset.to_le_bytes());
        memory.write_array(0x2000, cb).unwrap();
        memory.write_array(0x1800, 0x2000u64.to_le_bytes()).unwrap();
        assert_eq!(
            value(
                source
                    .start(2, [id, 1, 0x1800, 0, 0, 0], &mut memory, 1, &target, None)
                    .unwrap()
            ),
            Err(Errno(22))
        );
        assert!(queue.host.lock().unwrap().is_empty());
    }
}
