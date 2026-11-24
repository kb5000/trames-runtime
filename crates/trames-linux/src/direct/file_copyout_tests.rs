// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{
    Memory, MemoryError, PageBacking, PageSource, PageWait, Permissions, SharedPage, PAGE_SIZE,
};

pub(in crate::direct) struct Deferred {
    wait: Arc<PageWait>,
    bytes: Mutex<Option<Arc<SharedPage>>>,
    identity: u64,
}
impl Deferred {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            wait: Arc::default(),
            bytes: Mutex::default(),
            identity: trames_memory::new_backing_identity(),
        })
    }
    pub(in crate::direct) fn finish(&self) {
        *self.bytes.lock().unwrap() = Some(Arc::new(SharedPage::new([0; PAGE_SIZE as usize])));
        self.wait.finish();
    }
}
impl PageSource for Deferred {
    fn load(&self) -> Result<Arc<SharedPage>, MemoryError> {
        self.bytes
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| self.wait.fault(0))
    }
}
struct Backing(Arc<Deferred>);
impl PageBacking for Backing {
    fn check(&self, _: u64) -> Result<(), MemoryError> {
        Ok(())
    }
    fn page_source(&self) -> Option<Arc<dyn PageSource>> {
        Some(self.0.clone())
    }
    fn cpu_borrow_safe(&self) -> bool {
        true
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.0.identity, 0))
    }
    fn read(&self, at: usize, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.0.load()?.copy_read(at, bytes);
        Ok(())
    }
    fn write(&self, at: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        self.0.load()?.copy_write(at, bytes);
        Ok(())
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn publish_write(&self, _: usize, _: usize) -> Result<(), MemoryError> {
        Ok(())
    }
    fn sync_required(&self) -> bool {
        false
    }
    fn version(&self) -> u64 {
        0
    }
    fn writable(&self) -> bool {
        true
    }
    fn next_page(&self, _: u64) -> Result<Arc<dyn PageBacking>, MemoryError> {
        Err(MemoryError::InvalidRange)
    }
}
fn destination() -> (Memory, Arc<Deferred>, u64) {
    let mut memory = Memory::default();
    memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    let page = install(&mut memory, 0x10000 + PAGE_SIZE);
    (memory, page, 0x10000 + PAGE_SIZE - 2)
}
pub(in crate::direct) fn install(memory: &mut Memory, address: u64) -> Arc<Deferred> {
    let page = Deferred::new();
    memory
        .map_backed(
            address,
            vec![Arc::new(Backing(page.clone()))],
            true,
            Permissions::RW,
            false,
        )
        .unwrap();
    page
}
#[test]
fn output_wait_keeps_its_cursor_instead_of_overwriting_an_already_copied_prefix() {
    for worker in [false, true] {
        let (mut memory, page, address) = destination();
        let mut copy = FileCopyout::new(
            &FileOutput::Scalar(address),
            Ok(trames_vfs::FileValue::Bytes(b"abcdefgh".to_vec())),
        );
        if worker {
            let mut view = memory.parallel_view(&mut Default::default()).unwrap();
            let fault = copy.progress(&mut view).unwrap_err();
            assert_eq!(fault.address, address + 2);
            view.write(address, b"XY").unwrap();
            page.finish();
            assert_eq!(copy.progress(&mut view), Ok(Ok(8)));
            assert_eq!(view.read_array::<8>(address).unwrap(), *b"XYcdefgh");
        } else {
            let fault = copy.progress(&mut memory).unwrap_err();
            assert_eq!(fault.address, address + 2);
            memory.write(address, b"XY").unwrap();
            page.finish();
            assert_eq!(copy.progress(&mut memory), Ok(Ok(8)));
            assert_eq!(memory.read_array::<8>(address).unwrap(), *b"XYcdefgh");
        }
    }
}
#[test]
fn a_read_reports_only_the_copied_prefix_when_the_remaining_destination_disappears() {
    let (mut memory, _page, address) = destination();
    let mut copy = FileCopyout::new(
        &FileOutput::Scalar(address),
        Ok(trames_vfs::FileValue::Bytes(b"abcdefgh".to_vec())),
    );
    assert_eq!(copy.progress(&mut memory).unwrap_err().address, address + 2);
    memory.unmap(address + 2, PAGE_SIZE).unwrap();
    assert_eq!(copy.progress(&mut memory), Ok(Ok(2)));
    assert_eq!(memory.read_array::<2>(address).unwrap(), *b"ab");
    assert_eq!(
        copy.progress(&mut memory),
        Ok(Ok(2)),
        "a completed short read cannot replay its copy"
    );
}
#[test]
fn a_fault_before_any_read_bytes_still_returns_efault() {
    let mut memory = Memory::default();
    let mut copy = FileCopyout::new(
        &FileOutput::Scalar(0x1000),
        Ok(trames_vfs::FileValue::Bytes(b"data".to_vec())),
    );
    assert_eq!(copy.progress(&mut memory), Ok(Err(Errno(14))));
}
#[test]
fn stat_output_keeps_its_inline_body_and_copied_prefix_across_a_page_wait() {
    let (mut memory, page, address) = destination();
    let mut copy = FileCopyout::new(
        &FileOutput::Stat(address),
        Ok(trames_vfs::FileValue::Stat([42; 128])),
    );
    assert_eq!(copy.progress(&mut memory).unwrap_err().address, address + 2);
    memory.write(address, b"XY").unwrap();
    page.finish();
    assert_eq!(copy.progress(&mut memory), Ok(Ok(0)));
    let bytes = memory.read_array::<128>(address).unwrap();
    assert_eq!(&bytes[..2], b"XY");
    assert!(bytes[2..].iter().all(|&byte| byte == 42));
}
#[test]
fn accepted_file_result_survives_page_wait_fd_reuse_and_source_rebinding_once() {
    struct Target;
    impl IoWake for Target {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    let target: Arc<dyn IoWake> = Arc::new(Target);
    for remove_destination in [false, true] {
        let mut v = trames_vfs::Vfs::default();
        v.import_file(b"/original", b"abcdefgh".to_vec()).unwrap();
        v.import_file(b"/replacement", b"other".to_vec()).unwrap();
        let fd = v.open_at(-100, b"/original", 0, 0).unwrap();
        let duplicate = v.dup(fd, 0, false).unwrap();
        let original = v
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        let outcome = trames_vfs::FileWork::new(
            &v.path_queries(),
            original,
            trames_vfs::FileCommand::Read {
                count: 8,
                offset: None,
            },
        )
        .run();
        assert!(matches!(&outcome, trames_vfs::FileOutcome::Complete(_)));
        assert_eq!(
            v.seek(duplicate, 0, 1),
            Err(Errno(11)),
            "copyout retains the original position"
        );
        v.shared_files().close_range(fd, fd, 0, 1).unwrap();
        assert_eq!(v.open_at(-100, b"/replacement", 0, 0).unwrap(), fd);
        let result = Arc::new(FileResult::default());
        result.complete(outcome);
        let (mut memory, page, address) = destination();
        let direct = DirectSyscalls::default();
        let args = [fd as u64, address, 8, 0, 0, 0];
        let attempt = direct.start_retained_file(
            FilePending::new(result, FileOutput::Scalar(address), None),
            63,
            args,
            &mut memory,
            1,
            &Arc::downgrade(&target),
        );
        let IoAttempt::Blocked(wait) = attempt else {
            panic!("missing page must retain accepted output")
        };
        assert_eq!(direct.completed.get(), 1);
        assert_eq!(wait.interruptible_file_wait(), Some(false));
        assert!(!wait.signal.ready());
        let accepted = wait.file_pending().unwrap();
        drop(wait);
        let IoAttempt::Blocked(wait) = direct.start_retained_file(
            accepted,
            63,
            args,
            &mut memory,
            2,
            &Arc::downgrade(&target),
        ) else {
            panic!("still waiting")
        };
        assert_eq!(v.seek(duplicate, 0, 1), Err(Errno(11)));
        if remove_destination {
            memory.unmap(address + 2, PAGE_SIZE).unwrap();
        }
        page.finish();
        assert!(wait.signal.ready());
        let expected = if remove_destination { 2 } else { 8 };
        assert!(
            matches!(direct.resume(wait, &mut memory), IoAttempt::Complete(Ok(n)) if n == expected)
        );
        assert_eq!(
            direct.completed.get(),
            1,
            "IO completion must not be accounted twice"
        );
        assert_eq!(memory.read_array::<2>(address).unwrap(), *b"ab");
        if !remove_destination {
            assert_eq!(memory.read_array::<8>(address).unwrap(), *b"abcdefgh");
        }
        assert_eq!(
            v.seek(fd, 0, 1),
            Ok(0),
            "copy retry never resolves the reused FD"
        );
        assert_eq!(
            v.seek(duplicate, 0, 1),
            Ok(expected),
            "only the copied prefix advances the original OFD"
        );
    }
}

#[test]
fn pread_holds_its_original_ofd_through_copyout_but_fstat_releases_after_snapshot() {
    struct Target;
    impl IoWake for Target {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    let target: Arc<dyn IoWake> = Arc::new(Target);
    for stat in [false, true] {
        for cancel in [false, true] {
            let mut v = trames_vfs::Vfs::default();
            v.import_file(b"/original", b"abcdefgh".to_vec()).unwrap();
            v.import_file(b"/replacement", b"other".to_vec()).unwrap();
            let fd = v.open_at(-100, b"/original", 2, 0).unwrap();
            let lock = v.normalize_ofd_lock(fd, 1, 0, 0, 0).unwrap();
            v.retain_record_lock(fd, lock).unwrap().try_lock().unwrap();
            let peer = v.open_at(-100, b"/original", 2, 0).unwrap();
            let lock = v.normalize_ofd_lock(peer, 1, 0, 0, 0).unwrap();
            let competitor = v.retain_record_lock(peer, lock).unwrap();
            assert_eq!(competitor.try_lock(), Err(Errno(11)));
            let original = v
                .shared_files()
                .lookup(fd)
                .unwrap()
                .unwrap()
                .file_target()
                .unwrap();
            let command = if stat {
                trames_vfs::FileCommand::Stat
            } else {
                trames_vfs::FileCommand::Read {
                    count: 8,
                    offset: Some(0),
                }
            };
            let outcome = trames_vfs::FileWork::new(&v.path_queries(), original, command).run();
            assert!(matches!(&outcome, trames_vfs::FileOutcome::Complete(_)));
            v.close(fd).unwrap();
            assert_eq!(v.open_at(-100, b"/replacement", 0, 0).unwrap(), fd);
            let result = Arc::new(FileResult::default());
            result.complete(outcome);
            let (mut memory, page, address) = destination();
            let direct = DirectSyscalls::default();
            let (number, args, output) = if stat {
                (
                    80,
                    [fd as u64, address, 0, 0, 0, 0],
                    FileOutput::Stat(address),
                )
            } else {
                (
                    67,
                    [fd as u64, address, 8, 0, 0, 0],
                    FileOutput::Scalar(address),
                )
            };
            let attempt = direct.start_retained_file(
                FilePending::new(result, output, None),
                number,
                args,
                &mut memory,
                1,
                &Arc::downgrade(&target),
            );
            let IoAttempt::Blocked(wait) = attempt else {
                panic!("accepted output must wait for its second page")
            };
            assert_eq!(
                competitor.try_lock(),
                if stat { Ok(()) } else { Err(Errno(11)) },
                "Linux drops fstat's FD before user copy, and pread's FD afterward"
            );
            if cancel {
                drop(wait);
            } else {
                page.finish();
                assert!(
                    matches!(direct.resume(wait, &mut memory), IoAttempt::Complete(Ok(n)) if n == if stat { 0 } else { 8 })
                );
                if stat {
                    assert_eq!(
                        memory.read_array::<8>(address + 48).unwrap(),
                        8u64.to_le_bytes()
                    );
                } else {
                    assert_eq!(memory.read_array::<8>(address).unwrap(), *b"abcdefgh");
                }
            }
            assert_eq!(
                competitor.try_lock(),
                Ok(()),
                "completion and cancellation release only the original OFD lease"
            );
        }
    }
}

#[test]
fn ordinary_path_outputs_keep_the_accepted_result_across_unlink_and_fd_reuse() {
    struct Target;
    impl IoWake for Target {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    let target: Arc<dyn IoWake> = Arc::new(Target);
    for number in [78, 79, 80, 291] {
        let mut v = trames_vfs::Vfs::default();
        v.import_file(b"/original", b"abcdefgh".to_vec()).unwrap();
        v.symlink_at(b"accepted-target", -100, b"/link").unwrap();
        let fd = v.open_at(-100, b"/original", 0, 0).unwrap();
        let direct = DirectSyscalls::default().with_paths(v.path_queries());
        let (mut memory, page, address) = destination();
        memory.write(0x10100, b"/link\0").unwrap();
        memory.write(0x10120, b"/original\0").unwrap();
        let args = match number {
            78 => [(-100i64) as u64, 0x10100, address, (1u64 << 32) + 8, 0, 0],
            79 => [(-100i64) as u64, 0x10120, address, 0, 0, 0],
            80 => [fd as u64, address, 0, 0, 0, 0],
            291 => [fd as u64, 0, 0x1000, 0x7ff, address, 0],
            _ => unreachable!(),
        };
        assert_eq!(
            direct.invoke_path(number, args, &mut memory),
            None,
            "syscall {number}"
        );
        assert_eq!(direct.completed.get(), 1);
        if number == 78 {
            v.unlink_at(-100, b"/link", false).unwrap();
            v.symlink_at(b"replacement", -100, b"/link").unwrap();
        } else {
            v.close(fd).unwrap();
            v.unlink_at(-100, b"/original", false).unwrap();
            v.import_file(b"/original", b"other".to_vec()).unwrap();
            assert_eq!(v.open_at(-100, b"/original", 0, 0).unwrap(), fd);
        }
        let attempt = direct
            .start_prepared_file(number, args, &mut memory, 1, &Arc::downgrade(&target))
            .unwrap();
        let IoAttempt::Blocked(wait) = attempt else {
            panic!("original output must still be waiting")
        };
        page.finish();
        assert!(
            matches!(direct.resume(wait, &mut memory), IoAttempt::Complete(Ok(n)) if n == if number == 78 { 8 } else { 0 })
        );
        assert_eq!(direct.completed.get(), 1);
        if number == 78 {
            assert_eq!(memory.read_array::<8>(address).unwrap(), *b"accepted");
        } else {
            let offset = if number == 291 { 40 } else { 48 };
            assert_eq!(
                memory.read_array::<8>(address + offset).unwrap(),
                8u64.to_le_bytes()
            );
        }
    }
}

#[test]
fn readlink_rejects_nonpositive_int_lengths_before_importing_the_path() {
    let v = trames_vfs::Vfs::default();
    let direct = DirectSyscalls::default().with_paths(v.path_queries());
    let mut memory = Memory::default();
    for raw in [0, 1u64 << 32, u32::MAX as u64, 0x80000000] {
        assert_eq!(
            direct.invoke_path(78, [(-100i64) as u64, 0, 0, raw, 0, 0], &mut memory),
            Some(Err(Errno(22)))
        );
    }
}
