// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering::Relaxed},
    Mutex,
};
use trames_memory::{Memory, PageWait, Permissions, PAGE_SIZE};
use trames_vfs::{PidNamespace, Pty, TerminalAccess, Vfs};

#[test]
fn userfault_control_retains_original_mm_from_a_foreign_caller_without_async_pages() {
    let vfs = Vfs::default();
    let mut original = Memory::default();
    original.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    original.memory_report().bind_read_waker(Arc::new(|_| {}));
    let file = original.userfaultfd(false);
    let fd = vfs
        .descriptor_factory()
        .userfaultfd(file.clone(), trames_vfs::O_NONBLOCK)
        .unwrap();
    assert!(vfs
        .fd_flags_snapshot()
        .descriptor_control(fd)
        .unwrap()
        .shared_file()
        .userfault_file()
        .is_some());
    let source = source(&vfs);
    let mut foreign = Memory::default();
    foreign.map(0x1000, PAGE_SIZE * 3, Permissions::RW).unwrap();
    assert!(!foreign.async_faults_possible());
    foreign
        .write_array(
            0x1000,
            [
                0xaa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        )
        .unwrap();
    assert_eq!(
        source.invoke(29, args(fd, 0xc018aa3f, 0x1000), &mut foreign),
        Some(Ok(0))
    );
    assert!(file.initialized());
    let mut register = [0; 32];
    register[0..8].copy_from_slice(&0x10000u64.to_le_bytes());
    register[8..16].copy_from_slice(&PAGE_SIZE.to_le_bytes());
    register[16..24].copy_from_slice(&1u64.to_le_bytes());
    foreign.write(0x1000, &register).unwrap();
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let target = Arc::downgrade(&wake);
    let wait = blocked(
        source
            .start(
                29,
                args(fd, 0xc020aa00, 0x1000),
                &mut foreign,
                7,
                &target,
                None,
            )
            .unwrap(),
    );
    assert!(original.activate_proc_reads());
    assert!(matches!(
        source.resume(wait, &mut foreign),
        IoAttempt::Complete(Ok(0))
    ));
    let MemoryError::Pending(fault) = original.read_array::<1>(0x10000).unwrap_err() else {
        panic!("registered original mm must fault")
    };
    foreign.write(0x2000, &[42; PAGE_SIZE as usize]).unwrap();
    let mut copy = [0; 40];
    for (i, value) in [0x10000u64, 0x2000, PAGE_SIZE, 0, 0].iter().enumerate() {
        copy[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    foreign.write(0x1000, &copy).unwrap();
    let wait = blocked(
        source
            .start(
                29,
                args(fd, 0xc028aa03, 0x1000),
                &mut foreign,
                7,
                &target,
                None,
            )
            .unwrap(),
    );
    assert!(original.activate_proc_reads());
    assert!(matches!(
        source.resume(wait, &mut foreign),
        IoAttempt::Complete(Ok(0))
    ));
    assert!(fault.wait.ready());
    assert_eq!(original.read_array::<1>(0x10000).unwrap(), [42]);
}

#[test]
fn userfault_copy_keeps_imported_bytes_across_original_budget_pressure_and_fd_reuse() {
    let mut vfs = Vfs::default();
    let mut original = Memory::new(1 << 20);
    original.set_total_limit(1 << 20).unwrap();
    original.map(0x10000, 1 << 20, Permissions::RW).unwrap();
    original.memory_report().bind_read_waker(Arc::new(|_| {}));
    let pressure = original.memory_pressure(None);
    let _monitor = pressure.monitor(b"some 1 1000000", true).unwrap();
    let actor = Arc::new(trames_memory::CgroupMemoryTarget::default());
    actor.bind_pressure(&pressure);
    let _scope = actor.scope();
    for page in 0..240 {
        original.write(0x10000 + page * PAGE_SIZE, &[17]).unwrap();
    }
    let destination = 0x10000 + 240 * PAGE_SIZE;
    let file = original.userfaultfd(false);
    file.initialize().unwrap();
    let register = file.register(destination, PAGE_SIZE).unwrap();
    assert!(original.activate_proc_reads());
    assert_eq!(
        register.result(),
        Some(Ok((1u64 << 2 | 1 << 3 | 1 << 4).to_le_bytes().to_vec()))
    );
    let fd = vfs.descriptor_factory().userfaultfd(file, 0).unwrap();
    let source = source(&vfs);
    let mut foreign = Memory::default();
    foreign.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
    foreign.write(0x2000, &[42; PAGE_SIZE as usize]).unwrap();
    for (i, value) in [destination, 0x2000, PAGE_SIZE, 0, 0]
        .into_iter()
        .enumerate()
    {
        foreign
            .write(0x1000 + i as u64 * 8, &value.to_le_bytes())
            .unwrap();
    }
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let target = Arc::downgrade(&wake);
    let wait = blocked(
        source
            .start(
                29,
                args(fd, 0xc028aa03, 0x1000),
                &mut foreign,
                7,
                &target,
                None,
            )
            .unwrap(),
    );
    let before = original.resident_bytes();
    assert!(original.activate_proc_reads());
    let wait = blocked(source.resume(wait, &mut foreign));
    assert_eq!(original.resident_bytes(), before);
    foreign.write(0x2000, &[99; PAGE_SIZE as usize]).unwrap();
    vfs.close(fd).unwrap();
    assert_eq!(vfs.eventfd(0, 0).unwrap(), fd);
    original.unmap(0x10000, 16 * PAGE_SIZE).unwrap();
    let wait = blocked(source.resume(wait, &mut foreign));
    assert!(original.activate_proc_reads());
    assert!(matches!(
        source.resume(wait, &mut foreign),
        IoAttempt::Complete(Ok(0))
    ));
    assert_eq!(original.read_array::<1>(destination).unwrap(), [42]);
    assert_eq!(
        foreign.read_array::<8>(0x1020).unwrap(),
        PAGE_SIZE.to_le_bytes()
    );
}

#[test]
fn concurrent_userfault_api_negotiation_clears_the_losing_response_after_copyout() {
    let vfs = Vfs::default();
    let mut original = Memory::default();
    let file = original.userfaultfd(false);
    let fd = vfs
        .descriptor_factory()
        .userfaultfd(file.clone(), trames_vfs::O_NONBLOCK)
        .unwrap();
    let source = source(&vfs);
    let mut first = Gate::new(false, true);
    let mut second = Gate::new(false, false);
    let mut api = [0; 24];
    api[0] = 0xaa;
    first.memory.write(0x3000, &api).unwrap();
    second.memory.write(0x3000, &api).unwrap();
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let target = Arc::downgrade(&wake);
    let pending = blocked(
        source
            .start(
                29,
                args(fd, 0xc018aa3f, 0x3000),
                &mut first,
                7,
                &target,
                None,
            )
            .unwrap(),
    );
    assert!(!file.initialized());
    assert_eq!(
        source.invoke(29, args(fd, 0xc018aa3f, 0x3000), &mut second),
        Some(Ok(0))
    );
    first.write_wait.finish();
    assert!(matches!(
        source.resume(pending, &mut first),
        IoAttempt::Complete(Err(Errno(22)))
    ));
    assert_eq!(first.memory.read_array::<24>(0x3000).unwrap(), [0; 24]);
    assert!(file.initialized());
}

// Independent waits allow a readable input page to fault only on copyout,
// as with a private file mapping that needs write/COW preparation.
struct Gate {
    memory: Memory,
    read_wait: Arc<PageWait>,
    write_wait: Arc<PageWait>,
    probe: Option<Arc<Pty>>,
}
impl Gate {
    fn new(read: bool, write: bool) -> Self {
        let mut memory = Memory::default();
        memory.map(0x1000, 0x5000, Permissions::RW).unwrap();
        let gate = Self {
            memory,
            read_wait: Arc::default(),
            write_wait: Arc::default(),
            probe: None,
        };
        if !read {
            gate.read_wait.finish();
        }
        if !write {
            gate.write_wait.finish();
        }
        gate
    }
    fn fault(&self, address: u64, length: usize, wait: &Arc<PageWait>) -> Result<(), MemoryError> {
        if !wait.ready() && address < 0x4000 && address.saturating_add(length as u64) > 0x3000 {
            Err(wait.fault(address.max(0x3000)))
        } else {
            Ok(())
        }
    }
}
impl CpuMemory for Gate {
    fn mapped_at_or_after(&self, address: u64) -> bool {
        self.memory.mapped_at_or_after(address)
    }
    fn async_faults_possible(&self) -> bool {
        true
    }
    fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.fault(address, bytes.len(), &self.read_wait)?;
        self.memory.read(address, bytes)
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if let Some(pair) = self.probe.take() {
            pair.terminal.borrow_mut().window = [9; 8];
        }
        self.fault(address, bytes.len(), &self.write_wait)?;
        self.memory.write(address, bytes)
    }
    fn check(&self, address: u64, length: usize, access: Access) -> Result<(), MemoryError> {
        self.memory.check(address, length, access)
    }
    fn check_translation(&self, address: u64) -> Result<(), MemoryError> {
        self.memory.check_translation(address)
    }
    fn fetch_u32(&self, address: u64) -> Result<u32, MemoryError> {
        self.memory.fetch_u32(address)
    }
    fn instruction_identity(&self) -> (u64, u64, u64) {
        self.memory.instruction_identity()
    }
    fn instruction_page_identity(&self, address: u64) -> Result<(u64, u64, u64), MemoryError> {
        self.memory.instruction_page_identity(address)
    }
    fn atomic_update<T>(
        &mut self,
        _: u64,
        _: usize,
        _: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError> {
        unreachable!("ioctl test")
    }
    fn exclusive_read(&mut self, _: u64, _: &mut [u8]) -> Result<u128, MemoryError> {
        unreachable!("ioctl test")
    }
    fn exclusive_write(&mut self, _: u64, _: &[u8], _: Option<u128>) -> Result<bool, MemoryError> {
        unreachable!("ioctl test")
    }
}
struct Wake;
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn runtime_info() -> trames_vfs::RuntimeInfo {
    trames_vfs::RuntimeInfo {
        processes: vec![trames_vfs::ProcessInfo {
            pid: 7,
            tgid: 7,
            ..Default::default()
        }],
        ..Default::default()
    }
}
fn device_fs() -> Vfs {
    let mut vfs = Vfs::default();
    vfs.set_runtime_info(7, runtime_info());
    vfs
}
fn source(vfs: &Vfs) -> DirectSyscalls {
    DirectSyscalls::new(vfs.direct_descriptors())
        .with_paths(vfs.path_queries())
        .with_resources(vfs.descriptor_factory())
}
fn args(fd: u32, request: u32, address: u64) -> [u64; 6] {
    [fd as u64, request as u64, address, 0, 0, 0]
}
fn blocked(attempt: IoAttempt) -> PendingIo {
    let IoAttempt::Blocked(wait) = attempt else {
        panic!("original ioctl must wait");
    };
    wait
}
fn value(attempt: IoAttempt) -> Result<u64, Errno> {
    let IoAttempt::Complete(value) = attempt else {
        panic!("original ioctl must finish");
    };
    value
}
fn start(
    source: &DirectSyscalls,
    args: [u64; 6],
    memory: &mut impl CpuMemory,
    wake: &Arc<dyn IoWake>,
) -> PendingIo {
    blocked(
        source
            .start(29, args, memory, 7, &Arc::downgrade(wake), None)
            .unwrap(),
    )
}
fn probe(vfs: &mut Vfs) -> u32 {
    let fd = vfs.eventfd(0, 0).unwrap();
    vfs.close(fd).unwrap();
    fd
}
fn timeline(vfs: &mut Vfs) -> u32 {
    vfs.open_at(-100, b"/dev/sw_sync", 2, 0).unwrap()
}
fn fence(vfs: &Vfs, memory: &mut Memory, timeline: u32, target: u32) -> u32 {
    let mut data = [0; 40];
    data[..4].copy_from_slice(&target.to_le_bytes());
    data[4..9].copy_from_slice(b"test\0");
    memory.write_array(0x1100, data).unwrap();
    vfs.sync_file(timeline)
        .unwrap()
        .unwrap()
        .ioctl(&vfs.descriptor_factory(), 0xc0285700, 0x1100, memory)
        .unwrap();
    u32::from_le_bytes(memory.read_array::<4>(0x1124).unwrap())
}
fn increment(vfs: &Vfs, memory: &mut Memory, timeline: u32, amount: u32) {
    memory.write_array(0x1200, amount.to_le_bytes()).unwrap();
    vfs.sync_file(timeline)
        .unwrap()
        .unwrap()
        .ioctl(&vfs.descriptor_factory(), 0x40045701, 0x1200, memory)
        .unwrap();
}
struct Task {
    namespace: PidNamespace,
    access: TerminalAccess,
    signals: Mutex<Vec<u32>>,
    ready: Arc<trames_vfs::Readiness>,
    ignored: AtomicBool,
}
impl trames_vfs::TerminalSignals for Task {
    fn signal(&self, _: u32, _: u32, number: u32) {
        self.signals.lock().unwrap().push(number);
    }
    fn clear_session(&self, _: u32, _: u32) {}
    fn hangup(&self, _: u32, _: u32, _: u32) {}
}
impl TerminalTask for Task {
    fn namespace(&self) -> &PidNamespace {
        &self.namespace
    }
    fn access(&self) -> TerminalAccess {
        self.access
    }
    fn ignored(&self, _: u32) -> bool {
        self.ignored.load(Relaxed)
    }
    fn orphaned(&self) -> bool {
        false
    }
    fn subscribe_job(&self, signal: &Arc<IoSignal>) -> Option<IoSubscription> {
        Some(self.ready.subscribe(signal))
    }
    fn visible(&self, id: u32) -> u32 {
        id
    }
    fn foreground(&self, _: u32, group: u32) -> Result<u32, Errno> {
        Ok(group)
    }
    fn acquire(&self, _: &Arc<Pty>, _: bool, _: bool, _: bool) -> Result<(), Errno> {
        Ok(())
    }
    fn detach(&self, _: &Arc<Pty>, _: bool) -> Result<(), Errno> {
        Ok(())
    }
}
fn tty(vfs: &mut Vfs) -> (u32, Arc<trames_vfs::PtyEnd>, Arc<Task>) {
    let fd = vfs.open_at(-100, b"/dev/ptmx", 2, 0).unwrap();
    let end = vfs.pty(fd).unwrap().unwrap();
    {
        let mut tty = end.pair.terminal.borrow_mut();
        tty.session = 1;
        tty.foreground = 1;
    }
    let task = Arc::new(Task {
        namespace: Default::default(),
        access: TerminalAccess {
            session: 1,
            group: 1,
            controlling: Some(end.pair.id),
            ignore_ttou: false,
        },
        signals: Mutex::default(),
        ready: Arc::default(),
        ignored: AtomicBool::new(false),
    });
    (fd, end, task)
}
#[test]
fn readable_count_is_one_scalar_snapshot_on_original_ofd_after_close_and_reuse() {
    let mut vfs = device_fs();
    let [fd, writer] = vfs.pipe(0).unwrap();
    let alias = vfs.dup(fd, 0, false).unwrap();
    vfs.write(writer, b"abc").unwrap();
    let source = source(&vfs);
    let mut memory = Gate::new(false, true);
    memory.memory.write_array(0x2ffe, [0x55; 4]).unwrap();
    let a = args(fd, 0x541b, 0x2ffe);
    assert_eq!(source.invoke(29, a, &mut memory), None);
    assert_eq!(memory.memory.read_array::<2>(0x2ffe).unwrap(), [0x55; 2]);
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let wait = start(&source, a, &mut memory, &wake);
    assert_eq!(wait.interruptible_file_wait(), Some(false));
    vfs.close(fd).unwrap();
    assert_eq!(vfs.eventfd(99, 0).unwrap(), fd);
    assert_eq!(vfs.read(alias, 2).unwrap(), b"ab");
    vfs.write(writer, b"def").unwrap();
    memory.write_wait.finish();
    assert!(wait.signal.ready());
    drop(source);
    assert_eq!(
        value(DirectSyscalls::default().resume(wait, &mut memory)),
        Ok(0)
    );
    assert_eq!(
        memory.memory.read_array::<4>(0x2ffe).unwrap(),
        3u32.to_le_bytes()
    );
    assert_eq!(vfs.read(fd, 8).unwrap(), 99u64.to_le_bytes());
}
#[test]
fn fionbio_keeps_input_fragments_and_original_pipe_until_cancel_or_completion() {
    for cancel in [false, true] {
        let mut vfs = device_fs();
        let [fd, writer] = vfs.pipe(0).unwrap();
        let alias = vfs.dup(fd, 0, false).unwrap();
        let source = source(&vfs);
        let mut memory = Gate::new(true, false);
        memory
            .memory
            .write_array(0x2ffe, 1u32.to_le_bytes())
            .unwrap();
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let wait = start(&source, args(fd, 0x5421, 0x2ffe), &mut memory, &wake);
        vfs.close(fd).unwrap();
        assert_eq!(vfs.eventfd(0, 0).unwrap(), fd);
        memory.memory.write_array(0x2ffe, [0; 2]).unwrap();
        assert_eq!(vfs.flags(alias).unwrap() & trames_vfs::O_NONBLOCK, 0);
        if cancel {
            wait.cancel_copies();
        }
        memory.read_wait.finish();
        assert_eq!(
            value(source.resume(wait, &mut memory)),
            if cancel { Err(Errno(4)) } else { Ok(0) }
        );
        assert_eq!(
            vfs.flags(alias).unwrap() & trames_vfs::O_NONBLOCK,
            if cancel { 0 } else { trames_vfs::O_NONBLOCK }
        );
        assert_eq!(vfs.flags(fd).unwrap() & trames_vfs::O_NONBLOCK, 0);
        assert_eq!(vfs.write(writer, b"x"), Ok(1));
    }
}
#[test]
fn sync_create_keeps_unpublished_slot_and_original_input_through_copyout_wait() {
    let mut vfs = device_fs();
    let timeline = timeline(&mut vfs);
    let expected = probe(&mut vfs);
    let source = source(&vfs);
    let mut memory = Gate::new(false, true);
    let mut data = [0; 40];
    data[..4].copy_from_slice(&5u32.to_le_bytes());
    data[4..13].copy_from_slice(b"original\0");
    memory.memory.write_array(0x2ff0, data).unwrap();
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let wait = start(
        &source,
        args(timeline, 0xc0285700, 0x2ff0),
        &mut memory,
        &wake,
    );
    assert!(vfs.sync_file(expected).is_err());
    let next = vfs.eventfd(0, 0).unwrap();
    assert_ne!(next, expected);
    memory
        .memory
        .write_array(0x2ff0, 9u32.to_le_bytes())
        .unwrap();
    increment(&vfs, &mut memory.memory, timeline, 5);
    memory.write_wait.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(
        memory.memory.read_array::<4>(0x2ff0).unwrap(),
        9u32.to_le_bytes()
    );
    let published = u32::from_le_bytes(memory.memory.read_array::<4>(0x3014).unwrap());
    assert_eq!(published, expected);
    assert_eq!(vfs.poll(published, 1), 1);
}
#[test]
fn sync_create_cancel_and_copy_failure_release_original_hidden_slot_and_old_receipts() {
    for cancel in [false, true] {
        let mut vfs = device_fs();
        let timeline = timeline(&mut vfs);
        let expected = probe(&mut vfs);
        let source = source(&vfs);
        let mut memory = Gate::new(false, true);
        memory.memory.write_array(0x2ff0, [0; 40]).unwrap();
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let wait = start(
            &source,
            args(timeline, 0xc0285700, 0x2ff0),
            &mut memory,
            &wake,
        );
        let old = wait.file_pending().unwrap();
        if cancel {
            wait.cancel_copies();
            assert_eq!(probe(&mut vfs), expected);
        } else {
            memory.memory.unmap(0x3000, PAGE_SIZE).unwrap();
        }
        memory.write_wait.finish();
        assert_eq!(
            value(source.resume(wait, &mut memory)),
            Err(Errno(if cancel { 4 } else { 14 }))
        );
        assert_eq!(vfs.eventfd(0, 0).unwrap(), expected);
        drop(old);
    }
}
#[test]
fn sync_unused_slot_precedes_input_and_failed_merge_uses_native_enoent() {
    let mut vfs = device_fs();
    let timeline = timeline(&mut vfs);
    let mut memory = Gate::new(true, true);
    let fence = fence(&vfs, &mut memory.memory, timeline, 1);
    vfs.set_descriptor_limit(0);
    let source = source(&vfs);
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    assert_eq!(
        value(
            source
                .start(
                    29,
                    args(timeline, 0xc0285700, 0x90000),
                    &mut memory,
                    7,
                    &Arc::downgrade(&wake),
                    None
                )
                .unwrap()
        ),
        Err(Errno(24))
    );
    vfs.set_descriptor_limit(1024);
    let mut data = [0; 48];
    data[32..36].copy_from_slice(&999u32.to_le_bytes());
    memory.memory.write_array(0x1100, data).unwrap();
    assert_eq!(
        value(
            source
                .start(
                    29,
                    args(fence, 0xc0303e03, 0x1100),
                    &mut memory,
                    7,
                    &Arc::downgrade(&wake),
                    None
                )
                .unwrap()
        ),
        Err(Errno(2))
    );
    assert!(!memory.read_wait.ready());
    assert!(!memory.write_wait.ready());
}
#[test]
fn sync_merge_accepts_second_fd_after_input_and_keeps_its_original_fence_through_output() {
    let mut vfs = device_fs();
    let a = timeline(&mut vfs);
    let b = timeline(&mut vfs);
    let c = timeline(&mut vfs);
    let mut memory = Gate::new(true, true);
    let left = fence(&vfs, &mut memory.memory, a, 1);
    let right = fence(&vfs, &mut memory.memory, b, 2);
    let source = source(&vfs);
    let mut data = [0; 48];
    data[32..36].copy_from_slice(&right.to_le_bytes());
    memory.memory.write_array(0x2ff0, data).unwrap();
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let wait = start(&source, args(left, 0xc0303e03, 0x2ff0), &mut memory, &wake);
    vfs.close(right).unwrap();
    assert_eq!(fence(&vfs, &mut memory.memory, c, 3), right);
    memory.read_wait.finish();
    let wait = blocked(source.resume(wait, &mut memory));
    vfs.close(right).unwrap();
    assert_eq!(vfs.eventfd(0, 0).unwrap(), right);
    memory.write_wait.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    let merged = u32::from_le_bytes(memory.memory.read_array::<4>(0x3014).unwrap());
    increment(&vfs, &mut memory.memory, a, 1);
    increment(&vfs, &mut memory.memory, b, 2);
    assert_eq!(vfs.poll(merged, 1), 0);
    increment(&vfs, &mut memory.memory, c, 3);
    assert_eq!(vfs.poll(merged, 1), 1);
}
#[test]
fn sync_info_keeps_original_records_and_header_when_fences_complete_during_output_wait() {
    let mut vfs = device_fs();
    let timeline = timeline(&mut vfs);
    let mut memory = Gate::new(false, true);
    let fd = fence(&vfs, &mut memory.memory, timeline, 1);
    let mut info = [0; 56];
    info[40..44].copy_from_slice(&1u32.to_le_bytes());
    info[48..56].copy_from_slice(&0x2ff0u64.to_le_bytes());
    memory.memory.write_array(0x1100, info).unwrap();
    let source = source(&vfs);
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let wait = start(&source, args(fd, 0xc0383e04, 0x1100), &mut memory, &wake);
    increment(&vfs, &mut memory.memory, timeline, 1);
    assert_eq!(vfs.poll(fd, 1), 1);
    memory.memory.write(0x2ff0, &[0x77; 16]).unwrap();
    memory.write_wait.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(memory.memory.read_array::<16>(0x2ff0).unwrap(), [0x77; 16]);
    assert_eq!(
        i32::from_le_bytes(memory.memory.read_array::<4>(0x3030).unwrap()),
        0
    );
    assert_eq!(memory.memory.read_array::<8>(0x3038).unwrap(), [0; 8]);
    assert_eq!(
        i32::from_le_bytes(memory.memory.read_array::<4>(0x1120).unwrap()),
        0
    );
}
#[test]
fn fuse_clone_keeps_destination_and_input_error_order_before_later_source_fd_lookup() {
    let mut vfs = device_fs();
    let fd = vfs.open_at(-100, b"/dev/fuse", 2, 0).unwrap();
    let source = source(&vfs);
    let mut memory = Gate::new(true, false);
    memory
        .memory
        .write_array(0x2ffe, 999u32.to_le_bytes())
        .unwrap();
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let wait = start(
        &source,
        args(fd, trames_vfs::fuse::CLONE, 0x2ffe),
        &mut memory,
        &wake,
    );
    vfs.close(fd).unwrap();
    assert_eq!(vfs.eventfd(0, 0).unwrap(), fd);
    memory.memory.write_array(0x2ffe, [0; 2]).unwrap();
    memory.read_wait.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Err(Errno(22)));
    let other = vfs.open_at(-100, b"/dev/fuse", 2, 0).unwrap();
    assert_eq!(
        value(
            source
                .start(
                    29,
                    args(other, trames_vfs::fuse::CLONE, 0x90000),
                    &mut memory,
                    7,
                    &Arc::downgrade(&wake),
                    None
                )
                .unwrap()
        ),
        Err(Errno(14))
    );
}
#[test]
fn terminal_attributes_import_without_a_state_lock_and_do_not_repeat_job_check_after_page_wait() {
    let mut vfs = device_fs();
    let (fd, end, task) = tty(&mut vfs);
    let source = source(&vfs).with_terminal_task(Some(task.clone()));
    let mut memory = Gate::new(true, false);
    let mut attrs = end.pair.terminal.borrow().attributes;
    attrs[0] ^= 1;
    memory.memory.write_array(0x2ff0, attrs).unwrap();
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let wait = start(&source, args(fd, 0x5402, 0x2ff0), &mut memory, &wake);
    assert!(task.signals.lock().unwrap().is_empty());
    end.pair.terminal.borrow_mut().foreground = 2;
    memory.memory.write(0x2ff0, &[0x77; 16]).unwrap();
    memory.read_wait.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(end.pair.terminal.borrow().attributes, attrs);
    assert!(task.signals.lock().unwrap().is_empty());
}
#[test]
fn terminal_query_keeps_original_snapshot_prefix_and_endpoint_after_fd_reuse() {
    let mut vfs = device_fs();
    let (fd, end, task) = tty(&mut vfs);
    let source = source(&vfs).with_terminal_task(Some(task));
    let mut memory = Gate::new(false, true);
    let original = end.pair.terminal.borrow().attributes;
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let wait = start(&source, args(fd, 0x5401, 0x2ff0), &mut memory, &wake);
    assert_eq!(
        memory.memory.read_array::<16>(0x2ff0).unwrap(),
        original[..16]
    );
    end.pair.terminal.borrow_mut().attributes = [0x11; 36];
    vfs.close(fd).unwrap();
    assert_eq!(vfs.eventfd(0, 0).unwrap(), fd);
    memory.memory.write(0x2ff0, &[0x77; 16]).unwrap();
    memory.write_wait.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(memory.memory.read_array::<16>(0x2ff0).unwrap(), [0x77; 16]);
    let mut tail = [0; 20];
    memory.memory.read(0x3000, &mut tail).unwrap();
    assert_eq!(tail, original[16..]);
    assert_eq!(end.pair.terminal.borrow().attributes, [0x11; 36]);
}
#[test]
fn terminal_job_stop_uses_original_notification_then_becomes_an_uninterruptible_input_copy() {
    let mut vfs = device_fs();
    let (fd, end, task) = tty(&mut vfs);
    end.pair.terminal.borrow_mut().foreground = 2;
    let source = source(&vfs).with_terminal_task(Some(task.clone()));
    let mut memory = Gate::new(true, false);
    let attrs = end.pair.terminal.borrow().attributes;
    memory.memory.write_array(0x2ff0, attrs).unwrap();
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let wait = start(&source, args(fd, 0x5402, 0x2ff0), &mut memory, &wake);
    assert_eq!(*task.signals.lock().unwrap(), vec![22]);
    assert_eq!(wait.interruptible_file_wait(), Some(true));
    assert!(!wait.signal.ready());
    end.pair.terminal.borrow_mut().foreground = 1;
    task.ready.notify_atomic();
    assert!(wait.signal.ready());
    let wait = blocked(source.resume(wait, &mut memory));
    assert_eq!(wait.interruptible_file_wait(), Some(false));
    assert!(wait.notification_external());
    assert!(!wait.signal.ready());
    end.pair.terminal.borrow_mut().foreground = 2;
    memory.read_wait.finish();
    assert!(wait.signal.ready());
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(*task.signals.lock().unwrap(), vec![22]);
    assert_eq!(end.pair.terminal.borrow().attributes, attrs);
}
#[test]
fn window_update_signals_original_task_once_and_stale_copy_cannot_repeat_it() {
    let mut vfs = device_fs();
    let (fd, end, task) = tty(&mut vfs);
    let source = source(&vfs).with_terminal_task(Some(task.clone()));
    let mut memory = Gate::new(true, false);
    memory.memory.write_array(0x2ffc, [3u8; 8]).unwrap();
    let a = args(fd, 0x5414, 0x2ffc);
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let wait = start(&source, a, &mut memory, &wake);
    let stale = wait.file_pending().unwrap();
    assert!(task.signals.lock().unwrap().is_empty());
    memory.memory.write(0x2ffc, &[0x77; 4]).unwrap();
    memory.read_wait.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(end.pair.terminal.borrow().window, [3; 8]);
    assert_eq!(*task.signals.lock().unwrap(), vec![28]);
    assert_eq!(
        value(source.start_retained_file(stale, 29, a, &mut memory, 7, &Arc::downgrade(&wake))),
        Err(Errno(4))
    );
    assert_eq!(*task.signals.lock().unwrap(), vec![28]);
}
#[test]
fn public_terminal_query_releases_state_lock_before_the_actual_faultable_write() {
    let mut vfs = device_fs();
    let (_fd, end, task) = tty(&mut vfs);
    end.pair.terminal.borrow_mut().window = [3; 8];
    let mut memory = Gate::new(false, true);
    memory.probe = Some(end.pair.clone());
    assert_eq!(
        crate::terminal_query(&end, 0x5413, 0x2ffc, task.as_ref(), &mut memory),
        Err(Errno(14))
    );
    assert_eq!(memory.memory.read_array::<4>(0x2ffc).unwrap(), [3; 4]);
    assert_eq!(end.pair.terminal.borrow().window, [9; 8]);
}
#[test]
fn perf_id_and_namespace_owner_keep_one_original_scalar_across_output_wait_and_fd_reuse() {
    for perf in [false, true] {
        let mut vfs = device_fs();
        vfs.set_runtime_info(7, runtime_info());
        let mut memory = Gate::new(false, true);
        let (fd, request, expected) = if perf {
            let mut attr = [0; 64];
            attr[..4].copy_from_slice(&1u32.to_le_bytes());
            attr[4..8].copy_from_slice(&64u32.to_le_bytes());
            attr[8..16].copy_from_slice(&1u64.to_le_bytes());
            memory.memory.write_array(0x1100, attr).unwrap();
            let attr = trames_vfs::perf::Attr::read(&mut memory.memory, 0x1100).unwrap();
            let view = trames_vfs::ProcessView::default();
            let fd = vfs
                .descriptor_factory()
                .perf_event(attr, view.perf_clock(), None, false)
                .unwrap();
            (fd, 0x80082407, vfs.perf_event(fd).unwrap().unwrap().id())
        } else {
            let fd = vfs.open_at(-100, b"/proc/self/ns/user", 0, 0).unwrap();
            (fd, 0xb704, vfs.namespace_owner_uid(fd).unwrap() as u64)
        };
        let source = source(&vfs);
        memory.memory.write_array(0x2ffe, [0x55; 8]).unwrap();
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let wait = start(&source, args(fd, request, 0x2ffe), &mut memory, &wake);
        assert_eq!(memory.memory.read_array::<2>(0x2ffe).unwrap(), [0x55; 2]);
        vfs.close(fd).unwrap();
        assert_eq!(vfs.eventfd(0, 0).unwrap(), fd);
        memory.write_wait.finish();
        assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
        if perf {
            assert_eq!(
                memory.memory.read_array::<8>(0x2ffe).unwrap(),
                expected.to_le_bytes()
            );
        } else {
            assert_eq!(
                memory.memory.read_array::<4>(0x2ffe).unwrap(),
                (expected as u32).to_le_bytes()
            );
        }
    }
}
#[test]
fn tun_attach_happens_once_before_copyout_and_survives_copy_failure_or_cancellation() {
    for mode in 0..3 {
        let mut vfs = device_fs();
        vfs.configure_network(trames_vfs::NetworkMode::Full)
            .unwrap();
        let fd = vfs.open_at(-100, b"/dev/net/tun", 2, 0).unwrap();
        let before = vfs.network_devices().len();
        let source = source(&vfs);
        let mut memory = Gate::new(false, true);
        let mut ifreq = [0; 40];
        ifreq[..5].copy_from_slice(b"tun%d");
        ifreq[16..18].copy_from_slice(&0x1001u16.to_le_bytes());
        memory.memory.write_array(0x2ff0, ifreq).unwrap();
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let wait = start(&source, args(fd, 0x400454ca, 0x2ff0), &mut memory, &wake);
        assert_eq!(vfs.network_devices().len(), before + 1);
        assert_eq!(
            vfs.tun_file(fd).unwrap().unwrap().interface().unwrap().0,
            b"tun0"
        );
        memory.memory.write(0x2ff0, b"changed\0").unwrap();
        if mode == 1 {
            memory.memory.unmap(0x3000, PAGE_SIZE).unwrap();
        }
        if mode == 2 {
            wait.cancel_copies();
        }
        memory.write_wait.finish();
        assert_eq!(
            value(source.resume(wait, &mut memory)),
            match mode {
                1 => Err(Errno(14)),
                2 => Err(Errno(4)),
                _ => Ok(0),
            }
        );
        assert_eq!(vfs.network_devices().len(), before + 1);
        assert_eq!(
            vfs.tun_file(fd).unwrap().unwrap().interface().unwrap().0,
            b"tun0"
        );
        assert_eq!(
            memory.memory.read_array::<8>(0x2ff0).unwrap(),
            *b"changed\0"
        );
    }
}
#[test]
fn ifconf_keeps_records_before_its_final_length_store_and_preserves_header_pointer_and_padding() {
    let mut vfs = device_fs();
    vfs.configure_network(trames_vfs::NetworkMode::Full)
        .unwrap();
    let fd = vfs.socket(2, 2, 0).unwrap();
    let source = source(&vfs);
    let mut memory = Gate::new(false, true);
    let mut header = [0; 16];
    header[..4].copy_from_slice(&64u32.to_le_bytes());
    header[8..16].copy_from_slice(&0x2ff0u64.to_le_bytes());
    memory.memory.write_array(0x1100, header).unwrap();
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let wait = start(&source, args(fd, 0x8912, 0x1100), &mut memory, &wake);
    assert_eq!(
        memory.memory.read_array::<4>(0x1100).unwrap(),
        64u32.to_le_bytes()
    );
    memory.memory.write(0x2ff0, &[0x77; 16]).unwrap();
    memory.memory.write_array(0x1104, [0x33; 4]).unwrap();
    memory
        .memory
        .write_array(0x1108, 0x90000u64.to_le_bytes())
        .unwrap();
    memory.write_wait.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(
        memory.memory.read_array::<4>(0x1100).unwrap(),
        40u32.to_le_bytes()
    );
    assert_eq!(memory.memory.read_array::<4>(0x1104).unwrap(), [0x33; 4]);
    assert_eq!(memory.memory.read_u64(0x1108).unwrap(), 0x90000);
    assert_eq!(memory.memory.read_array::<16>(0x2ff0).unwrap(), [0x77; 16]);
    assert_eq!(
        u16::from_le_bytes(memory.memory.read_array::<2>(0x3000).unwrap()),
        2
    );
    header[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    header[8..16].copy_from_slice(&0x90000u64.to_le_bytes());
    memory.memory.write_array(0x1100, header).unwrap();
    assert_eq!(
        value(
            source
                .start(
                    29,
                    args(fd, 0x8912, 0x1100),
                    &mut memory,
                    7,
                    &Arc::downgrade(&wake),
                    None
                )
                .unwrap()
        ),
        Ok(0)
    );
    assert_eq!(memory.memory.read_array::<4>(0x1100).unwrap(), [0; 4]);
    assert_eq!(memory.memory.read_u64(0x1108).unwrap(), 0x90000);
}
#[test]
fn nested_ethtool_command_keeps_original_device_decision_and_accepted_input_fragments() {
    let mut vfs = device_fs();
    vfs.configure_network(trames_vfs::NetworkMode::Full)
        .unwrap();
    let tun = vfs.open_at(-100, b"/dev/net/tun", 2, 0).unwrap();
    vfs.tun_file(tun)
        .unwrap()
        .unwrap()
        .attach(b"query0", 0x1001, true)
        .unwrap();
    let fd = vfs.socket(2, 2, 0).unwrap();
    let device = vfs
        .network_devices()
        .into_iter()
        .find(|device| device.name == b"query0")
        .unwrap();
    let source = source(&vfs);
    let mut memory = Gate::new(true, false);
    let mut ifreq = [0; 40];
    ifreq[..device.name.len()].copy_from_slice(&device.name);
    ifreq[16..24].copy_from_slice(&0x2ffeu64.to_le_bytes());
    memory.memory.write_array(0x1100, ifreq).unwrap();
    memory
        .memory
        .write_array(0x2ffe, 0x41u32.to_le_bytes())
        .unwrap();
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let wait = start(&source, args(fd, 0x8946, 0x1100), &mut memory, &wake);
    vfs.configure_network_device(device.index, Some(b"renamed"), None, None)
        .unwrap();
    memory.memory.write_array(0x2ffe, [0x99; 2]).unwrap();
    memory.read_wait.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(
        memory.memory.read_array::<4>(0x2ffe).unwrap(),
        0x41u32.to_le_bytes()
    );
    assert_eq!(
        i32::from_le_bytes(memory.memory.read_array::<4>(0x3006).unwrap()),
        -1
    );
}
#[test]
fn render_discovery_keeps_multiple_outputs_ordered_after_fd_reuse_and_never_replays_prefixes() {
    let mut vfs = device_fs();
    vfs.enable_video_device();
    let fd = vfs.open_at(-100, b"/dev/dri/renderD128", 2, 0).unwrap();
    let source = source(&vfs);
    let mut memory = Gate::new(false, true);
    let description = b"Trames virtual render device";
    let mut header = [0; 64];
    for (offset, capacity, pointer) in [
        (16, 6u64, 0x2100u64),
        (32, 8, 0x2ffc),
        (48, description.len() as u64, 0x4100),
    ] {
        header[offset..offset + 8].copy_from_slice(&capacity.to_le_bytes());
        header[offset + 8..offset + 16].copy_from_slice(&pointer.to_le_bytes());
    }
    memory.memory.write_array(0x1100, header).unwrap();
    memory
        .memory
        .write(0x4100, &vec![0x55; description.len()])
        .unwrap();
    let mut a = args(fd, 0xc0406400, 0x1100);
    a[1] |= 0xffff_ffff_0000_0000;
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let wait = start(&source, a, &mut memory, &wake);
    assert_eq!(memory.memory.read_array::<6>(0x2100).unwrap(), *b"trames");
    assert_eq!(memory.memory.read_array::<4>(0x2ffc).unwrap(), *b"2026");
    let mut untouched = vec![0; description.len()];
    memory.memory.read(0x4100, &mut untouched).unwrap();
    assert_eq!(untouched, vec![0x55; description.len()]);
    memory.memory.write(0x2100, b"custom").unwrap();
    memory.memory.write(0x2ffc, b"YYZZ").unwrap();
    vfs.close(fd).unwrap();
    assert_eq!(vfs.eventfd(0, 0).unwrap(), fd);
    memory.write_wait.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(memory.memory.read_array::<6>(0x2100).unwrap(), *b"custom");
    assert_eq!(memory.memory.read_array::<8>(0x2ffc).unwrap(), *b"YYZZ1031");
    memory.memory.read(0x4100, &mut untouched).unwrap();
    assert_eq!(untouched, description);
    assert_eq!(
        memory.memory.read_array::<4>(0x1100).unwrap(),
        1u32.to_le_bytes()
    );
}
#[test]
fn slot_controls_without_factory_defer_before_input_instead_of_creating_an_unfillable_checkpoint() {
    let mut vfs = device_fs();
    let [fd, _writer] = vfs.pipe(0).unwrap();
    let partial = DirectSyscalls::new(vfs.direct_descriptors());
    let mut memory = Gate::new(true, false);
    memory
        .memory
        .write_array(0x2ffe, 1u32.to_le_bytes())
        .unwrap();
    let a = args(fd, 0x5421, 0x2ffe);
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    assert!(partial
        .start(29, a, &mut memory, 7, &Arc::downgrade(&wake), None)
        .is_none());
    assert!(!partial.file_prepared(29, a));
    assert_eq!(vfs.flags(fd).unwrap() & trames_vfs::O_NONBLOCK, 0);
    assert!(!memory.read_wait.ready());
    let owner = source(&vfs);
    let wait = start(&owner, a, &mut memory, &wake);
    memory.read_wait.finish();
    assert_eq!(value(owner.resume(wait, &mut memory)), Ok(0));
    assert_ne!(vfs.flags(fd).unwrap() & trames_vfs::O_NONBLOCK, 0);
}
#[test]
fn binder_classification_keeps_entire_original_file_before_worker_start_and_page_wait() {
    let mut vfs = device_fs();
    vfs.set_lock_owner(7);
    vfs.set_runtime_info(7, runtime_info());
    let fd = vfs.open_at(-100, b"/dev/binder", 2, 0).unwrap();
    let source = source(&vfs);
    let mut memory = Gate::new(false, true);
    let a = args(fd, trames_vfs::binder::abi::VERSION, 0x2ffe);
    assert_eq!(source.invoke(29, a, &mut memory), None);
    vfs.close(fd).unwrap();
    assert_eq!(vfs.eventfd(99, 0).unwrap(), fd);
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let attempt = source
        .start(29, a, &mut memory, 7, &Arc::downgrade(&wake), None)
        .unwrap();
    let IoAttempt::FileCheckpoint(checkpoint) = attempt else {
        panic!("original typed Binder handoff");
    };
    let file::FileBoundary::Ioctl(call) = checkpoint.take() else {
        panic!("original ioctl");
    };
    let wait = blocked(call.resume(&source, &mut memory, 7, &Arc::downgrade(&wake)));
    assert!(wait.binder.is_some());
    memory.memory.write(0x2ffe, b"XY").unwrap();
    memory.write_wait.finish();
    assert_eq!(
        value(DirectSyscalls::default().resume(wait, &mut memory)),
        Ok(0)
    );
    assert_eq!(
        memory.memory.read_array::<4>(0x2ffe).unwrap(),
        [b'X', b'Y', 0, 0]
    );
    assert_eq!(vfs.read(fd, 8).unwrap(), 99u64.to_le_bytes());
}
#[test]
fn bare_ioctl_dispatch_retains_registers_snapshot_and_original_ofd_until_resume_or_handoff() {
    for handoff in [false, true] {
        let mut linux = Linux::new(0x10000);
        let [fd, writer] = linux.vfs.pipe(0).unwrap();
        linux.vfs.write(writer, b"abc").unwrap();
        let mut memory = Memory::default();
        memory.map(0x1000, 0x2000, Permissions::RW).unwrap();
        let page = file::copyout_tests::install(&mut memory, 0x3000);
        memory.write(0x2ffe, &[0x55; 2]).unwrap();
        let mut cpu = trames_execution::Aarch64State::default();
        cpu.registers[..6].copy_from_slice(&args(fd, 0x541b, 0x2ffe));
        cpu.registers[8] = 29;
        let original = cpu.clone();
        let mut output = crate::CapturedOutput::default();
        assert_eq!(
            linux.dispatch_task_untraced(7, &mut cpu, &mut memory, &mut output),
            crate::SyscallOutcome::Deferred
        );
        assert_eq!(cpu, original);
        linux.vfs.close(fd).unwrap();
        assert_eq!(linux.vfs.eventfd(99, 0).unwrap(), fd);
        assert_eq!(linux.vfs.write(writer, b"more"), Ok(4));
        if handoff {
            let wait = linux.take_ioctl_wait(7).unwrap();
            page.finish();
            assert_eq!(
                value(DirectSyscalls::default().resume(wait, &mut memory)),
                Ok(0)
            );
        } else {
            page.finish();
            assert_eq!(
                linux.dispatch_task_untraced(7, &mut cpu, &mut memory, &mut output),
                crate::SyscallOutcome::Continue
            );
            assert_eq!(cpu.registers[0], 0);
        }
        assert_eq!(memory.read_array::<4>(0x2ffe).unwrap(), 3u32.to_le_bytes());
        assert_eq!(linux.vfs.read(fd, 8).unwrap(), 99u64.to_le_bytes());
        assert_eq!(linux.vfs.write(writer, b"late"), Err(Errno(32)));
        assert!(linux.take_ioctl_wait(7).is_none());
    }
}
#[test]
fn bare_exit_invalidates_old_ioctl_receipts_and_releases_original_unused_slot_before_late_page() {
    for group in [false, true] {
        let mut linux = Linux::new(0x10000);
        linux.vfs.set_runtime_info(7, runtime_info());
        let fd = timeline(&mut linux.vfs);
        let expected = probe(&mut linux.vfs);
        let mut memory = Memory::default();
        memory.map(0x1000, 0x2000, Permissions::RW).unwrap();
        let page = file::copyout_tests::install(&mut memory, 0x3000);
        memory.write(0x2ff0, &[0; 16]).unwrap();
        let mut cpu = trames_execution::Aarch64State::default();
        cpu.registers[..6].copy_from_slice(&args(fd, 0xc0285700, 0x2ff0));
        cpu.registers[8] = 29;
        let mut output = crate::CapturedOutput::default();
        assert_eq!(
            linux.dispatch_task_untraced(7, &mut cpu, &mut memory, &mut output),
            crate::SyscallOutcome::Deferred
        );
        let Some(Solo::Io(wait)) = linux.ioctl_calls.get(&7) else {
            panic!("original input wait");
        };
        let old = wait.file_pending().unwrap();
        cpu.registers[0] = 0;
        cpu.registers[8] = if group { 94 } else { 93 };
        assert_eq!(
            linux.dispatch_task_untraced(7, &mut cpu, &mut memory, &mut output),
            crate::SyscallOutcome::Exit(0)
        );
        assert_eq!(linux.vfs.eventfd(0, 0).unwrap(), expected);
        assert!(linux.take_ioctl_wait(7).is_none());
        page.finish();
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        assert_eq!(
            value(DirectSyscalls::default().start_retained_file(
                old,
                29,
                args(fd, 0xc0285700, 0x2ff0),
                &mut memory,
                7,
                &Arc::downgrade(&wake)
            )),
            Err(Errno(4))
        );
    }
}
