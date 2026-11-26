// SPDX-License-Identifier: GPL-3.0-or-later
//! One accepted regular-file write, including its byte cursor and OFD position.
use super::*;
use trames_shared::FileTransactionLease;

#[derive(Clone, Copy)]
pub(crate) struct Policy<'a> {
    pub append: bool,
    pub defer_sync: bool,
    pub range_offset: u64,
    pub range_count: usize,
    pub limit: u64,
    pub end: &'a std::cell::Cell<Option<u64>>,
}
pub(super) struct CopyTail {
    from: u64,
    count: usize,
    offered: Arc<std::sync::atomic::AtomicUsize>,
}
pub(super) struct Cursor {
    lease: Option<FileTransactionLease>,
    position: Option<Position>,
    offset: u64,
    range_offset: u64,
    limit: usize,
    size_limit: u64,
    done: usize,
    data_done: bool,
    sync: Option<Sync>,
    signal: bool,
    append: bool,
}
struct Position {
    file: SharedFd,
    original: u64,
    end: u64,
    commit: bool,
}
impl Position {
    fn begin(file: SharedFd) -> Result<Self> {
        let mut position = file.open.file_position.lock().unwrap();
        if position.pending != 0 {
            return Err(Errno(11));
        }
        let original = position.value;
        position.pending += 1;
        drop(position);
        Ok(Self {
            file,
            original,
            end: original,
            commit: true,
        })
    }
}
impl Drop for Position {
    fn drop(&mut self) {
        {
            let mut position = self.file.open.file_position.lock().unwrap();
            if self.commit {
                position.value = self.end;
            }
            position.pending -= 1;
        }
        self.file.open.file_position.notify_pending();
    }
}
pub(super) struct Sync {
    operation: mapped::SyncOperation,
    plan: Option<mapped::DataSync>,
    data_done: bool,
}
impl Sync {
    fn new(data_only: bool) -> Self {
        Self {
            operation: mapped::SyncOperation::File(data_only),
            plan: None,
            data_done: false,
        }
    }
    fn step(&mut self, v: &Vfs, target: &FileTarget) -> Result<()> {
        let _writeback = trames_shared::FileTransactionScope::writeback();
        let open = &target.0.open;
        #[cfg(all(feature = "hostfs", unix))]
        if let (Some(file), mapped::SyncOperation::File(data_only)) =
            (&open.host_file, self.operation)
        {
            return if data_only {
                file.file.sync_data()
            } else {
                file.file.sync_all()
            }
            .map_err(storage::host_errno);
        }
        let node = open.node.as_ref().ok_or(Errno(22))?;
        if !self.data_done {
            if self.plan.is_none() {
                let n = node.borrow();
                let Content::File(data) = &n.content else {
                    return Err(Errno(22));
                };
                #[cfg(all(feature = "hostfs", unix))]
                let backend = open.host_file.is_none();
                #[cfg(not(all(feature = "hostfs", unix)))]
                let backend = true;
                self.plan = Some(mapped::DataSync::capture_operation(
                    data,
                    self.operation,
                    backend,
                )?);
            }
            let plan = self.plan.as_mut().unwrap();
            let result = {
                let _node = node.borrow();
                plan.run()
            };
            plan.notify();
            result?;
            self.data_done = true;
            self.plan = None;
        }
        let mapped::SyncOperation::File(data_only) = self.operation else {
            #[cfg(all(feature = "hostfs", unix))]
            if let (
                Some(file),
                mapped::SyncOperation::Range {
                    offset,
                    length,
                    flags,
                },
            ) = (&open.host_file, self.operation)
            {
                storage::sync_backing_range(&file.file, offset, length, flags)?;
            }
            return Ok(());
        };
        let n = node.borrow();
        let linked = n.links != 0;
        let filesystem = open
            .mount_resource
            .get()
            .map_or(&v.fs, |mount| &mount.fs)
            .clone();
        drop(n);
        if linked {
            filesystem
                .borrow()
                .sync_file_metadata(data_only, Some(node))?;
        }
        Ok(())
    }
}
enum Start {
    Ready(Box<Cursor>),
    Wait(Option<Arc<trames_memory::PageWait>>),
    Error(Errno),
}
impl Cursor {
    pub(super) fn interruptible(&self) -> bool {
        !self.data_done && !self.signal
    }
    pub(super) fn progress(&self) -> usize {
        self.done
    }
    pub(super) fn file_size_signal(&self) -> bool {
        self.signal
    }
    fn begin(work: &mut FileWork) -> Start {
        let target = work.target.as_ref().unwrap();
        let (explicit, requested_sync) = match &work.command {
            FileCommand::Write { offset, .. } => (*offset, None),
            FileCommand::WriteSync {
                offset, data_only, ..
            } => (*offset, Some(*data_only)),
            _ => unreachable!("regular write cursor"),
        };
        let node = target.0.open.node.as_ref().unwrap();
        let mut node = node.borrow_mut();
        let Content::File(data) = &mut node.content else {
            return Start::Error(Errno(22));
        };
        let lease = match data.begin_transaction() {
            Ok(Ok(lease)) => lease,
            Ok(Err(wait)) => return Start::Wait(Some(trames_memory::PageWait::resource(wait))),
            Err(error) => return Start::Error(error),
        };
        let position = if explicit.is_none() {
            match Position::begin(target.0.clone()) {
                Ok(position) => Some(position),
                Err(Errno(11)) => return Start::Wait(None),
                Err(error) => return Start::Error(error),
            }
        } else {
            None
        };
        let range_offset = explicit.unwrap_or_else(|| position.as_ref().unwrap().original);
        let flags = target.0.open.flags.get();
        let offset = if flags & 0x400 != 0 {
            data.len()
        } else {
            range_offset
        };
        let sync = fd_status::write_sync(flags, requested_sync).map(Sync::new);
        let bytes = match &mut work.command {
            FileCommand::Write { bytes, .. } | FileCommand::WriteSync { bytes, .. } => bytes,
            _ => unreachable!(),
        };
        if let Some(tail) = &work.copy_tail {
            if !bytes.is_empty()
                && offset == data.len()
                && tail.from.checked_add(bytes.len() as u64) == Some(offset)
                && tail.count > bytes.len()
            {
                *bytes = repeat_tail(bytes, tail.count);
            }
            tail.offered
                .store(bytes.len().min(storage::MAX_TRANSFER), Ordering::Relaxed);
        }
        Start::Ready(Box::new(Self {
            lease,
            position,
            offset,
            range_offset,
            limit: bytes.len().min(storage::MAX_TRANSFER),
            size_limit: work.paths.view.borrow().file_size_limit.get(),
            done: 0,
            data_done: false,
            sync,
            signal: false,
            append: flags & 0x400 != 0,
        }))
    }
    fn record(&mut self, count: usize) {
        self.done += count;
        if count != 0 {
            if let Some(position) = &mut self.position {
                position.end = self.offset + self.done as u64;
            }
        }
    }
    fn finish_data(&mut self) {
        self.data_done = true;
        self.lease.take();
        if self.sync.is_some() {
            if let Some(position) = &mut self.position {
                position.commit = false;
            }
        }
    }
}
impl FileWork {
    pub(crate) fn report_write_end(mut self, end: Arc<std::sync::atomic::AtomicU64>) -> Self {
        self.write_end = Some(end);
        self
    }
    pub(crate) fn copy_tail(
        mut self,
        from: u64,
        count: usize,
        offered: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        self.copy_tail = Some(CopyTail {
            from,
            count,
            offered,
        });
        self
    }
    pub(crate) fn cancelled_write_progress(&self) -> usize {
        self.write.as_ref().map_or(0, |cursor| {
            if cursor.data_done && cursor.sync.is_some() {
                0
            } else {
                cursor.done
            }
        })
    }
    pub(super) fn cursor_sync(&self) -> bool {
        let valid = match self.command {
            FileCommand::Sync { .. } => true,
            FileCommand::SyncRange {
                offset,
                length,
                flags,
            } => {
                flags != 0
                    && flags & !7 == 0
                    && offset <= i64::MAX as u64
                    && length <= i64::MAX as u64 - offset
            }
            _ => false,
        };
        valid
            && self.target.as_ref().is_some_and(|target| {
                target.regular_file()
                    && !target.daemon_backed()
                    && target.status_flags() & O_PATH == 0
            })
    }
    pub(super) fn run_sync(mut self) -> FileOutcome {
        let operation = match self.command {
            FileCommand::Sync { data_only } => mapped::SyncOperation::File(data_only),
            FileCommand::SyncRange {
                offset,
                length,
                flags,
            } => mapped::SyncOperation::Range {
                offset,
                length,
                flags,
            },
            _ => unreachable!("retained file sync"),
        };
        let sync = self.sync.get_or_insert_with(|| {
            Box::new(Sync {
                operation,
                plan: None,
                data_done: false,
            })
        });
        let scope = resource_io::Scope::enter();
        let reply = self.paths.file_operation(self.exclusive, |v| {
            sync.step(v, self.target.as_ref().unwrap())
                .map(|()| FileValue::Count(0))
        });
        if let Some(pending) = scope.finish() {
            self.resource_wait = Some(pending.wait);
            return FileOutcome::Waiting(self);
        }
        match reply {
            Some((result, _)) => {
                FileOutcome::Complete(Self::descriptor_result(result, &mut self.command))
            }
            None => self.defer_operation(),
        }
    }
    pub(super) fn cursor_write(&self) -> bool {
        let valid = match &self.command {
            FileCommand::Write { bytes, offset } | FileCommand::WriteSync { bytes, offset, .. } => {
                !bytes.is_empty() && offset.is_none_or(|offset| offset <= i64::MAX as u64)
            }
            _ => false,
        };
        valid
            && self.target.as_ref().is_some_and(|target| {
                target.regular_file()
                    && !target.daemon_backed()
                    && fd_can_write(target.0.open.flags.get())
                    && target
                        .0
                        .open
                        .node
                        .as_ref()
                        .is_some_and(|node| node.text_users.load(Ordering::Relaxed) >= 0)
                    && target
                        .0
                        .open
                        .mount_resource
                        .get()
                        .is_none_or(|mount| !mount.readonly())
            })
    }
    pub(super) fn run_write(mut self) -> FileOutcome {
        if self.write.is_none() {
            match Cursor::begin(&mut self) {
                Start::Ready(cursor) => self.write = Some(cursor),
                Start::Wait(wait) => {
                    self.resource_wait = wait;
                    return FileOutcome::Waiting(self);
                }
                Start::Error(error) => return self.finish_write(Err(error)),
            }
        }
        let target = self.target.as_ref().unwrap().clone();
        let cursor = self.write.as_mut().unwrap();
        if !cursor.data_done {
            let scope = resource_io::Scope::enter();
            let _transaction = cursor.lease.as_ref().map(FileTransactionLease::enter);
            let bytes = match &self.command {
                FileCommand::Write { bytes, .. } | FileCommand::WriteSync { bytes, .. } => bytes,
                _ => unreachable!(),
            };
            let end = std::cell::Cell::new(None);
            let policy = Policy {
                append: cursor.append && cursor.done == 0,
                defer_sync: true,
                range_offset: cursor.range_offset,
                range_count: cursor.limit,
                limit: cursor.size_limit,
                end: &end,
            };
            let reply = self.paths.file_operation(self.exclusive, |v| {
                let descriptor = Descriptor {
                    open: OpenHandle::Shared(target.0.open.clone()),
                    cloexec: false.into(),
                };
                v.file_write_description_inner::<false>(
                    &descriptor,
                    &bytes[cursor.done..cursor.limit],
                    Some(cursor.offset + cursor.done as u64),
                    None,
                    (0, 0),
                    &mut 0,
                    Some(policy),
                )
                .map(|count| FileValue::Count(count as u64))
            });
            let pending = scope.finish();
            if reply.is_none() && pending.is_none() {
                return self.defer_operation();
            }
            let (result, signal) = reply.unwrap_or_else(|| {
                (
                    Ok(FileValue::Count(pending.as_ref().unwrap().progress as u64)),
                    false,
                )
            });
            cursor.signal |= signal;
            let count = match result {
                Ok(FileValue::Count(count)) => count as usize,
                Err(_) if pending.is_some() => pending.as_ref().unwrap().progress,
                Err(error) if cursor.done == 0 => return self.finish_write(Err(error)),
                Err(_) => 0,
                _ => unreachable!("file write returns a byte count"),
            };
            if count != 0 {
                if let Some(end) = end.get() {
                    // HostFS must keep its original atomic append. Its native
                    // writer can choose a later EOF than the cached inode; use
                    // that actual first prefix to pin all following offsets.
                    cursor.offset = end
                        .checked_sub((cursor.done + count) as u64)
                        .expect("backend end precedes its committed prefix");
                }
            }
            cursor.record(count);
            if count != 0 {
                if let Some(end) = &self.write_end {
                    end.store(cursor.offset + cursor.done as u64, Ordering::Relaxed);
                }
            }
            drop(_transaction);
            if let Some(pending) = pending {
                self.resource_wait = Some(pending.wait);
                return FileOutcome::Waiting(self);
            }
            cursor.finish_data();
        }
        let cursor = self.write.as_mut().unwrap();
        if let Some(sync) = &mut cursor.sync {
            let scope = resource_io::Scope::enter();
            let reply = self.paths.file_operation(self.exclusive, |v| {
                sync.step(v, &target).map(|()| FileValue::Count(0))
            });
            if let Some(pending) = scope.finish() {
                self.resource_wait = Some(pending.wait);
                return FileOutcome::Waiting(self);
            }
            match reply {
                Some((Ok(_), _)) => {}
                Some((Err(error), _)) => return self.finish_write(Err(error)),
                None => return self.defer_operation(),
            }
        }
        if let Some(position) = &mut self.write.as_mut().unwrap().position {
            position.commit = true;
        }
        let count = self.write.as_ref().unwrap().done as u64;
        self.finish_write(Ok(count))
    }
    pub(super) fn fail_write(mut self, error: Errno) -> FileOutcome {
        let cursor = self.write.as_mut().unwrap();
        if cursor.done == 0 || cursor.data_done {
            return self.finish_write(Err(error));
        }
        cursor.finish_data();
        self.run_write()
    }
    fn finish_write(mut self, result: Result<u64>) -> FileOutcome {
        let signal = self.write.as_ref().is_some_and(|cursor| cursor.signal);
        self.write.take();
        let scratch = match &mut self.command {
            FileCommand::Write { bytes, .. } | FileCommand::WriteSync { bytes, .. } => {
                Some(std::mem::take(bytes))
            }
            _ => None,
        };
        FileOutcome::Complete(FileReply {
            result: result.map(FileValue::Count),
            resources: Default::default(),
            file_size_signal: signal,
            scratch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::FileData;
    use std::sync::atomic::AtomicBool;
    use trames_memory::PageWait;
    use trames_shared::{SharedFile, SharedFileAccess, SharedFileAccounting, SharedFileCharge};

    struct Account {
        wait: Arc<PageWait>,
        boundary: usize,
        fail: AtomicBool,
    }
    struct Loan;
    impl SharedFileCharge for Loan {
        fn changed(&self) -> bool {
            true
        }
        fn commit(self: Box<Self>, _: usize) -> Arc<dyn Send + std::marker::Sync> {
            Arc::new(())
        }
    }
    impl SharedFileAccounting for Account {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn reserve(
            &self,
            offset: usize,
            _: usize,
            _: SharedFileAccess,
        ) -> std::io::Result<Box<dyn SharedFileCharge>> {
            if offset >= self.boundary {
                if !self.wait.ready() {
                    return Err(trames_shared::ResourcePending::io_error(self.wait.clone()));
                }
                if self.fail.load(Ordering::Relaxed) {
                    return Err(std::io::ErrorKind::PermissionDenied.into());
                }
            }
            Ok(Box::new(Loan))
        }
        fn truncate(&self, _: usize) {}
        fn write_chunk(&self, _: usize, length: usize) -> usize {
            length.min(2)
        }
    }
    fn target(v: &Vfs, fd: u32) -> FileTarget {
        v.shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap()
    }
    fn fixture(boundary: usize) -> (Vfs, u32, SharedFile, Arc<Account>) {
        fixture_in(Vfs::default(), boundary)
    }
    fn fixture_in(mut v: Vfs, boundary: usize) -> (Vfs, u32, SharedFile, Arc<Account>) {
        v.import_file(b"/original", b"base".to_vec()).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/original", 2 | 0x400, 0).unwrap();
        v.seek(fd, 3, 0).unwrap();
        let file = SharedFile::anonymous().unwrap();
        file.write_at(0, b"base").unwrap();
        let account = Arc::new(Account {
            wait: Arc::default(),
            boundary,
            fail: AtomicBool::new(false),
        });
        file.set_accounting(account.clone()).unwrap();
        target(&v, fd)
            .0
            .open
            .node
            .as_ref()
            .unwrap()
            .borrow_mut()
            .content = Content::File(FileData::Shared(file.clone()));
        (v, fd, file, account)
    }
    fn waiting(outcome: FileOutcome) -> FileWork {
        let FileOutcome::Waiting(work) = outcome else {
            panic!("expected a retained resource wait");
        };
        assert!(work.waiting());
        assert!(!work.ready());
        assert!(!work.host_work());
        work
    }
    fn count(outcome: FileOutcome) -> u64 {
        let FileOutcome::Complete(reply) = outcome else {
            panic!("expected completed original write");
        };
        assert!(!reply.file_size_signal);
        let FileValue::Count(count) = reply.result.unwrap() else {
            panic!("expected byte count");
        };
        count
    }
    fn buffer(work: &FileWork) -> (*const u8, usize) {
        let FileCommand::Write { bytes, .. } = &work.command else {
            panic!("expected original write buffer");
        };
        (bytes.as_ptr(), bytes.len())
    }
    #[test]
    fn retained_append_keeps_buffer_position_and_inode_across_close_reuse_and_a_contender() {
        for owned in [false, true] {
            let (mut v, fd, file, account) = fixture(6);
            let original = target(&v, fd);
            let next_fd = v.open_at(AT_FDCWD, b"/original", 2 | 0x400, 0).unwrap();
            let work = FileWork::new(
                &v.path_queries(),
                original.clone(),
                FileCommand::Write {
                    bytes: b"abcd".to_vec(),
                    offset: None,
                },
            );
            let input = buffer(&work);
            assert!(work.cursor_write(), "regular retained write predicate");
            let work = waiting(work.exclusive().run());
            assert!(
                work.write.is_some(),
                "original cursor must survive suspension"
            );
            assert_eq!(
                buffer(&work),
                input,
                "parking must not remove or copy a Vec prefix"
            );
            assert_eq!(file.read_at(0, 20).unwrap(), b"baseab");
            assert_eq!(original.0.open.file_position.snapshot(), 3);
            assert_eq!(original.0.open.file_position.lock().unwrap().pending, 1);
            let next = target(&v, next_fd);
            let command = FileCommand::Write {
                bytes: b"next".to_vec(),
                offset: None,
            };
            let next = waiting(if owned {
                FileWork::run_owned(&mut v, next, command)
            } else {
                FileWork::run_inline(&v.path_queries(), next, command)
            });
            v.close(fd).unwrap();
            assert_eq!(v.eventfd(7, 0).unwrap(), fd);
            account.wait.finish();
            assert!(work.ready());
            assert!(
                !next.ready(),
                "an append contender waits for the original data transaction"
            );
            assert_eq!(count(work.run()), 4);
            assert_eq!(original.0.open.file_position.snapshot(), 8);
            assert!(next.ready());
            assert_eq!(count(next.run()), 4);
            assert_eq!(file.read_at(0, 20).unwrap(), b"baseabcdnext");
            assert_eq!(v.read(fd, 8).unwrap(), 7u64.to_le_bytes());
        }
    }
    #[test]
    fn interrupt_and_exit_keep_the_committed_prefix_without_replaying_it() {
        for interrupted in [false, true] {
            let (v, fd, file, _) = fixture(6);
            let original = target(&v, fd);
            let work = waiting(FileWork::run_inline(
                &v.path_queries(),
                original.clone(),
                FileCommand::Write {
                    bytes: b"abcd".to_vec(),
                    offset: None,
                },
            ));
            assert!(
                work.interruptible_wait(),
                "its own pending position must not block a resource signal"
            );
            if interrupted {
                let reply = work.interrupted();
                assert!(matches!(reply.result, Ok(FileValue::Count(2))));
                assert_eq!(reply.scratch.unwrap(), b"abcd");
            } else {
                drop(work);
            }
            assert_eq!(file.read_at(0, 20).unwrap(), b"baseab");
            assert_eq!(original.0.open.file_position.snapshot(), 6);
            assert_eq!(original.0.open.file_position.lock().unwrap().pending, 0);
            assert!(
                file.begin_transaction().unwrap().is_some(),
                "cancellation releases only the original writer"
            );
        }
    }
    #[test]
    fn zero_progress_interrupt_does_not_jump_the_shared_position_to_append_eof() {
        let (v, fd, file, _) = fixture(4);
        let original = target(&v, fd);
        let work = waiting(FileWork::run_inline(
            &v.path_queries(),
            original.clone(),
            FileCommand::Write {
                bytes: b"abcd".to_vec(),
                offset: None,
            },
        ));
        assert_eq!(work.interrupted().result.err(), Some(Errno(4)));
        assert_eq!(original.0.open.file_position.snapshot(), 3);
        assert_eq!(file.read_at(0, 20).unwrap(), b"base");
    }
    #[test]
    fn explicit_append_and_a_real_error_after_the_prefix_preserve_original_position() {
        for explicit in [false, true] {
            let (mut v, fd, file, account) = fixture(6);
            let original = target(&v, fd);
            let work = waiting(FileWork::run_owned(
                &mut v,
                original.clone(),
                FileCommand::Write {
                    bytes: b"abcd".to_vec(),
                    offset: explicit.then_some(1),
                },
            ));
            account.fail.store(true, Ordering::Relaxed);
            account.wait.finish();
            assert_eq!(count(work.run()), 2);
            assert_eq!(file.read_at(0, 20).unwrap(), b"baseab");
            assert_eq!(
                original.0.open.file_position.snapshot(),
                if explicit { 3 } else { 6 }
            );
        }
    }
    #[test]
    fn sync_failure_after_resumed_append_preserves_bytes_and_rolls_back_the_original_position() {
        let directory = std::env::temp_dir().join(format!(
            "trames-cgroup-write-sync-{}-{}",
            std::process::id(),
            trames_memory::new_backing_identity()
        ));
        let v = Vfs::open_disk(&directory, Default::default()).unwrap();
        let (mut v, fd, file, account) = fixture_in(v, 6);
        let original = target(&v, fd);
        let disk = v.fs.borrow().disk.clone().unwrap();
        let work = waiting(FileWork::run_owned(
            &mut v,
            original.clone(),
            FileCommand::WriteSync {
                bytes: b"abcd".to_vec(),
                offset: None,
                data_only: false,
            },
        ));
        disk.fail_directory_syncs(2);
        account.wait.finish();
        let FileOutcome::Complete(reply) = work.run() else {
            panic!("resumed synchronous write must finish");
        };
        assert!(matches!(reply.result, Err(Errno(5))));
        assert_eq!(file.read_at(0, 20).unwrap(), b"baseabcd");
        assert_eq!(original.0.open.file_position.snapshot(), 3);
        assert_eq!(original.0.open.file_position.lock().unwrap().pending, 0);
        assert!(
            file.begin_transaction().unwrap().is_some(),
            "sync never retains the foreground data transaction"
        );
        disk.fail_directory_syncs(0);
        v.sync_fd(fd, false).unwrap();
        assert_eq!(original.0.open.file_position.snapshot(), 3);
        drop(reply);
        drop(original);
        drop(v);
        drop(disk);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[cfg(all(feature = "hostfs", unix))]
    #[test]
    fn native_append_uses_the_actual_host_end_after_an_external_writer_changes_eof() {
        use std::io::Write;
        let directory = std::env::temp_dir().join(format!(
            "trames-cgroup-host-append-{}-{}",
            std::process::id(),
            trames_memory::new_backing_identity()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("original");
        std::fs::write(&path, b"base").unwrap();
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/host", 0o700).unwrap();
        v.mount_host(b"/host", &directory, false).unwrap();
        let fd = v
            .open_at(AT_FDCWD, b"/host/original", 2 | 0x400, 0)
            .unwrap();
        let original = target(&v, fd);
        let mut work = FileWork::new(
            &v.path_queries(),
            original.clone(),
            FileCommand::Write {
                bytes: b"abcd".to_vec(),
                offset: None,
            },
        );
        let Start::Ready(cursor) = Cursor::begin(&mut work) else {
            panic!("original append admission");
        };
        assert_eq!(cursor.offset, 4);
        work.write = Some(cursor);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"TAIL")
            .unwrap();
        assert_eq!(count(work.run()), 4);
        assert_eq!(std::fs::read(&path).unwrap(), b"baseTAILabcd");
        assert_eq!(original.0.open.file_position.snapshot(), 12);
        drop(original);
        drop(v);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn controlled_direct_io_falls_back_before_bytes_or_shared_position_are_changed() {
        use trames_memory::{CgroupMemoryTarget, MemoryCgroup};
        let mut v = Vfs::default();
        v.import_file(b"/direct", b"base".to_vec()).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/direct", 2, 0).unwrap();
        let original = target(&v, fd);
        let mut epoch = FileEpoch::default();
        let direct = epoch.capture(&v, true).get(fd).unwrap();
        let actor = Arc::new(CgroupMemoryTarget::default());
        actor.set(Some(MemoryCgroup::new(None)));
        let scope = actor.scope();
        let mut cache = DiskReadCache::default();
        assert!(direct.read_reply(1, None, &mut cache).is_none());
        assert!(direct.write(b"XX", None, &mut cache).is_none());
        assert_eq!(original.0.open.file_position.snapshot(), 0);
        assert_eq!(original.0.open.file_position.lock().unwrap().pending, 0);
        assert_eq!(v.pread(fd, 4, 0).unwrap(), b"base");
        drop(scope);
        assert_eq!(direct.read(1, None, &mut cache), Some(Ok(b"b".to_vec())));
        assert_eq!(original.0.open.file_position.snapshot(), 1);
    }
    fn transfer_count(outcome: FileOutcome) -> u64 {
        let FileOutcome::Complete(reply) = outcome else {
            panic!("accepted transfer must complete");
        };
        assert!(!reply.file_size_signal);
        let FileValue::Transfer { count, .. } = reply.result.unwrap() else {
            panic!("transfer count");
        };
        count
    }
    #[test]
    fn copy_keeps_original_input_and_fd_identity_without_freezing_either_shared_position() {
        for explicit in [false, true] {
            let (mut v, _, file, account) = fixture(2);
            v.import_file(b"/source", b"abcd".to_vec()).unwrap();
            let input = v.open_at(AT_FDCWD, b"/source", 2, 0).unwrap();
            let output = v.open_at(AT_FDCWD, b"/original", 2, 0).unwrap();
            let source = target(&v, input);
            let dest = target(&v, output);
            let transfer = Arc::new(std::sync::Mutex::new(FileCopy::new(
                Ok(explicit.then_some(0)),
                Ok(explicit.then_some(0)),
                4,
                true,
            )));
            let FileOutcome::Waiting(work) = FileWork::run_owned(
                &mut v,
                dest.clone(),
                FileCommand::Copy {
                    input: source.clone(),
                    transfer: transfer.clone(),
                },
            ) else {
                panic!("copy retains partial output");
            };
            assert_eq!(file.read_at(0, 4).unwrap(), b"abse");
            assert_eq!(source.0.open.file_position.lock().unwrap().pending, 0);
            assert_eq!(dest.0.open.file_position.lock().unwrap().pending, 0);
            assert_eq!(v.seek(input, 3, 0), Ok(3));
            assert_eq!(v.seek(output, 3, 0), Ok(3));
            v.pwrite(input, b"wxyz", 0).unwrap();
            v.close(input).unwrap();
            assert_eq!(v.eventfd(17, 0).unwrap(), input);
            v.close(output).unwrap();
            assert_eq!(v.eventfd(19, 0).unwrap(), output);
            account.wait.finish();
            assert_eq!(transfer_count(work.run()), 4);
            assert_eq!(
                file.read_at(0, 4).unwrap(),
                b"abcd",
                "an accepted input is not re-read after the wait"
            );
            assert_eq!(
                source.0.open.file_position.snapshot(),
                if explicit { 3 } else { 4 }
            );
            assert_eq!(
                dest.0.open.file_position.snapshot(),
                if explicit { 3 } else { 4 }
            );
            assert!(
                transfer.lock().unwrap().stage.is_none(),
                "the old request snapshot does not retain a completed position"
            );
            assert_eq!(v.read(input, 8).unwrap(), 17u64.to_le_bytes());
            assert_eq!(v.read(output, 8).unwrap(), 19u64.to_le_bytes());
        }
    }
    #[test]
    fn cancelled_copy_publishes_only_its_committed_prefix_even_with_an_external_request_snapshot() {
        let (mut v, _, file, _) = fixture(2);
        v.import_file(b"/source", b"abcd".to_vec()).unwrap();
        let input = v.open_at(AT_FDCWD, b"/source", 0, 0).unwrap();
        let output = v.open_at(AT_FDCWD, b"/original", 2, 0).unwrap();
        let source = target(&v, input);
        let dest = target(&v, output);
        let transfer = Arc::new(std::sync::Mutex::new(FileCopy::new(
            Ok(None),
            Ok(None),
            4,
            true,
        )));
        let FileOutcome::Waiting(work) = FileWork::run_owned(
            &mut v,
            dest.clone(),
            FileCommand::Copy {
                input: source.clone(),
                transfer: transfer.clone(),
            },
        ) else {
            panic!("copy output wait");
        };
        drop(work);
        assert_eq!(file.read_at(0, 4).unwrap(), b"abse");
        assert_eq!(source.0.open.file_position.snapshot(), 2);
        assert_eq!(dest.0.open.file_position.snapshot(), 2);
        assert!(transfer.lock().unwrap().stage.is_none());
        assert!(file.begin_transaction().unwrap().is_some());
    }
    #[test]
    fn pipe_to_file_wait_keeps_the_prefix_and_cancel_or_short_write_consumes_it_once() {
        for completion in [0, 1, 2] {
            let (mut v, _, file, account) = fixture(2);
            let [input, producer] = v.pipe(O_NONBLOCK).unwrap();
            v.write(producer, b"abcdef").unwrap();
            let output = v.open_at(AT_FDCWD, b"/original", 2, 0).unwrap();
            let dest = target(&v, output);
            let source = v.shared_files().lookup(input).unwrap().unwrap();
            let transfer = Arc::new(std::sync::Mutex::new(StreamTransfer::new(
                source,
                dest.0.clone(),
                Ok(None),
                Ok(None),
                4,
                true,
                0,
            )));
            let FileOutcome::Waiting(work) = FileWork::run_owned(
                &mut v,
                dest.clone(),
                FileCommand::Transfer(transfer.clone()),
            ) else {
                panic!("splice output wait");
            };
            assert_eq!(
                v.read(input, 8),
                Err(Errno(11)),
                "the original pipe prefix remains reserved"
            );
            if completion == 0 {
                drop(work);
            } else {
                account.fail.store(completion == 2, Ordering::Relaxed);
                account.wait.finish();
                assert_eq!(
                    transfer_count(work.run()),
                    if completion == 1 { 4 } else { 2 }
                );
            }
            assert_eq!(
                v.read(input, 8).unwrap(),
                if completion == 1 {
                    b"ef".as_slice()
                } else {
                    b"cdef".as_slice()
                }
            );
            assert_eq!(
                file.read_at(0, 4).unwrap(),
                if completion == 1 {
                    b"abcd".as_slice()
                } else {
                    b"abse".as_slice()
                }
            );
            assert_eq!(
                dest.0.open.file_position.snapshot(),
                if completion == 1 { 4 } else { 2 }
            );
            assert_eq!(
                v.read(input, 8),
                Err(Errno(11)),
                "an old request snapshot cannot consume the prefix twice"
            );
            drop(transfer);
        }
    }
    #[test]
    fn forward_self_sendfile_keeps_the_original_repeat_tail_and_actual_output_end() {
        let mut v = Vfs::default();
        v.import_file(b"/self", b"abc".to_vec()).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/self", 2, 0).unwrap();
        v.seek(fd, 3, 0).unwrap();
        let original = target(&v, fd);
        let transfer = Arc::new(std::sync::Mutex::new(FileCopy::new(
            Ok(Some(0)),
            Ok(None),
            9,
            false,
        )));
        assert_eq!(
            transfer_count(FileWork::run_owned(
                &mut v,
                original.clone(),
                FileCommand::Copy {
                    input: original.clone(),
                    transfer
                }
            )),
            9
        );
        assert_eq!(v.pread(fd, 20, 0).unwrap(), b"abcabcabcabc");
        assert_eq!(original.0.open.file_position.snapshot(), 12);
    }
}
