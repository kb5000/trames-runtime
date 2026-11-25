// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted cross-resource transfers. Pipe reservations protect the original
//! prefix/capacity without holding a pipe mutex over disk I/O or a parked task.
use super::*;
use std::{io, time::Instant};

pub(super) struct ReadLease {
    pipe: Arc<PipeResource>,
}
impl ReadLease {
    pub(super) fn take(pipe: Arc<PipeResource>, count: usize) -> Result<(Self, Vec<u8>)> {
        let mut data = pipe.lock().unwrap();
        if data.read_reserved || data.bytes.is_empty() && data.writers != 0 {
            return Err(Errno(11));
        }
        let bytes = data.bytes.iter().take(count).copied().collect();
        data.read_reserved = true;
        data.io_epoch[0] = data.io_epoch[0].wrapping_add(1);
        drop(data);
        Ok((Self { pipe }, bytes))
    }
    pub(super) fn commit(&self, count: usize) {
        let mut data = self.pipe.lock().unwrap();
        data.bytes.drain(..count);
        if count != 0 {
            data.io_epoch[1] = data.io_epoch[1].wrapping_add(1);
        }
    }
}
impl Drop for ReadLease {
    fn drop(&mut self) {
        let mut data = self.pipe.lock().unwrap();
        data.read_reserved = false;
        data.io_epoch[0] = data.io_epoch[0].wrapping_add(1);
    }
}
impl read_reply::CommitRead for ReadLease {
    fn commit(&self, copied: usize) {
        ReadLease::commit(self, copied);
    }
}
pub(super) struct WriteLease {
    pipe: Arc<PipeResource>,
    pub(super) count: usize,
}
impl WriteLease {
    pub(super) fn take(pipe: Arc<PipeResource>, count: usize, file_pages: bool) -> Result<Self> {
        let mut data = pipe.lock().unwrap();
        if data.readers == 0 {
            return Err(Errno(32));
        }
        let count = count.min(data.transfer_room(file_pages));
        if count == 0 {
            return Err(Errno(11));
        }
        data.write_reserved += count;
        data.io_epoch[1] = data.io_epoch[1].wrapping_add(1);
        drop(data);
        Ok(Self { pipe, count })
    }
    pub(super) fn commit(&mut self, bytes: &[u8]) -> Result<usize> {
        let mut data = self.pipe.lock().unwrap();
        if data.readers == 0 {
            return Err(Errno(32));
        }
        data.bytes.extend(bytes);
        // Release our reserved capacity in the same transaction as publishing
        // bytes, so another writer never observes an overfull pipe.
        data.write_reserved -= self.count;
        self.count = 0;
        if !bytes.is_empty() {
            data.io_epoch[0] = data.io_epoch[0].wrapping_add(1);
        }
        data.io_epoch[1] = data.io_epoch[1].wrapping_add(1);
        Ok(bytes.len())
    }
}
impl Drop for WriteLease {
    fn drop(&mut self) {
        // A successful commit transfers this reservation into bytes and disarms
        // its count. Failed/cancelled reads return all reserved capacity.
        if self.count != 0 {
            let mut data = self.pipe.lock().unwrap();
            data.write_reserved -= self.count;
            data.io_epoch[1] = data.io_epoch[1].wrapping_add(1);
        }
    }
}
struct Stage {
    bytes: Vec<u8>,
    read: Option<ReadLease>,
    from: u64,
    written: Option<usize>,
}
/// Fully accepted original OFDs. Only one executing source/disk job owns this
/// state; FileWork moves it across readiness/layout boundaries without FD lookup.
pub struct StreamTransfer {
    pub(super) io: transfer_io::Io,
    pub(crate) input: SharedFd,
    pub(crate) output: SharedFd,
    from: Result<Option<u64>>,
    to: Result<Option<u64>>,
    requested: u64,
    mode: TransferMode,
    flags: u32,
    stage: Option<Stage>,
    blocked: Option<bool>, // true: output; false: input
    deadline: Option<Instant>,
    read_from: Option<u64>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum TransferMode {
    Sendfile,
    Splice,
    Tee,
}
pub struct TransferWait {
    pub subscriptions: Vec<IoSubscription>,
    pub native: Vec<(HostFd, bool)>,
    pub deadline: Option<Instant>,
}
impl StreamTransfer {
    pub(super) fn daemon_backed(&self) -> bool {
        [&self.input, &self.output].iter().any(|f| {
            matches!(
                f.open.control,
                Some(events::SharedControl::Fuse(_) | events::SharedControl::FuseFile(_))
            )
        })
    }
    pub fn admitted(input: &SharedFd, output: &SharedFd) -> bool {
        if [input, output]
            .iter()
            .any(|f| matches!(f.open.control, Some(events::SharedControl::Fuse(_))))
            && input.open.pipe.is_none()
            && output.open.pipe.is_none()
        {
            return false;
        }
        if input.open.pipe.is_some()
            && output
                .open
                .socket
                .as_ref()
                .is_some_and(|s| s.is_inet_message())
        {
            return input.open.control.is_none() && output.open.control.is_none();
        }
        [input, output].iter().all(|file| {
            let open = &file.open;
            (matches!(&open.control, Some(events::SharedControl::Fuse(_)))
                || matches!(&open.control, Some(events::SharedControl::FuseFile(file)) if file.regular()))
                || open.control.is_none()
                && (open.node.as_ref().is_some_and(|n| n.regular_file)
                    || open.pipe.is_some()
                    || open.local.as_ref().is_some_and(|s| s.kind() == 1)
                    || open.socket.as_ref().is_some_and(|s| s.is_stream()))
        })
    }
    pub fn new(
        input: SharedFd,
        output: SharedFd,
        from: Result<Option<u64>>,
        to: Result<Option<u64>>,
        count: u64,
        splice: bool,
        flags: u32,
    ) -> Self {
        Self {
            io: Default::default(),
            input,
            output,
            from,
            to,
            requested: count,
            mode: if splice {
                TransferMode::Splice
            } else {
                TransferMode::Sendfile
            },
            flags,
            stage: None,
            blocked: None,
            deadline: None,
            read_from: None,
        }
    }
    pub fn tee(input: SharedFd, output: SharedFd, count: u64, flags: u32) -> Result<Self> {
        let mut transfer = Self::new(input, output, Ok(None), Ok(None), count, true, flags);
        let source = &transfer.input.open;
        let dest = &transfer.output.open;
        if !fd_can_read(source.flags.get()) || !fd_can_write(dest.flags.get()) {
            return Err(Errno(9));
        }
        let (Some(reader), Some(writer)) = (&source.pipe, &dest.pipe) else {
            return Err(Errno(22));
        };
        if Arc::ptr_eq(&reader.data, &writer.data) {
            return Err(Errno(22));
        }
        if (source.flags.get() | dest.flags.get()) & O_NONBLOCK != 0 {
            transfer.flags |= 2;
        }
        transfer.mode = TransferMode::Tee;
        Ok(transfer)
    }
    pub fn tee_empty(count: u64, flags: u32) -> Option<Result<u64>> {
        if flags & !15 != 0 {
            Some(Err(Errno(22)))
        } else {
            (count == 0).then_some(Ok(0))
        }
    }
    fn count(&self) -> usize {
        self.requested.min(storage::MAX_TRANSFER as u64) as usize
    }
    fn descriptor(file: &SharedFd) -> Descriptor {
        Descriptor {
            open: OpenHandle::Shared(file.open.clone()),
            cloexec: false.into(),
        }
    }
    pub(crate) fn host_work(&self) -> bool {
        [&self.input, &self.output].iter().any(|f| {
            f.file_target().is_some_and(|target| {
                target.host_work(&FileCommand::Read {
                    count: self.count(),
                    offset: None,
                })
            })
        })
    }
    pub(crate) fn host_work_owned(&self) -> bool {
        // Match the existing joined short-read/write policy. Preserve queued
        // inode work and synchronous output; only a retained/bulk transfer
        // needs an island and a disk-pool round trip.
        [&self.input, &self.output].iter().any(|f| {
            f.open
                .node
                .as_ref()
                .is_some_and(|n| n.active_file_work.load(Ordering::Relaxed) != 0)
        }) || ((self.requested >= 16 * 1024 || self.output.open.flags.get() & 0x1000 != 0)
            && self.host_work())
    }
    pub(crate) fn waits(&self) -> bool {
        if self.io.blocked() {
            return true;
        }
        let Some(write) = self.blocked else {
            return false;
        };
        let file = if write { &self.output } else { &self.input };
        file.open.flags.get() & O_NONBLOCK == 0
            && !(self.mode != TransferMode::Sendfile
                && self.flags & 2 != 0
                && file.open.pipe.is_some())
            && !self.deadline.is_some_and(|d| Instant::now() >= d)
    }
    fn blocked(&mut self, write: bool) {
        self.blocked = Some(write);
        if self.deadline.is_none() {
            let file = if write { &self.output } else { &self.input };
            self.deadline = file
                .open
                .socket
                .as_ref()
                .and_then(|s| s.io_timeout(!write))
                .and_then(|d| Instant::now().checked_add(d));
        }
        // No output has committed. Return an accepted pipe prefix before
        // sleeping on a different resource; other readers can continue.
        if self.stage.as_ref().is_some_and(|s| s.read.is_some()) {
            self.stage = None;
        }
    }
    pub(crate) fn ready(&self) -> bool {
        if !self.waits() {
            return true;
        }
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            return true;
        }
        let Some(write) = self.blocked else {
            return true;
        };
        let file = if write { &self.output } else { &self.input };
        if let Some(pipe) = &file.open.pipe {
            let data = pipe.data.lock().unwrap();
            if write {
                data.readers == 0 || data.transfer_room(self.input.open.is_regular_file()) != 0
            } else {
                !data.read_reserved && (!data.bytes.is_empty() || data.writers == 0)
            }
        } else if let Some(socket) = &file.open.socket {
            socket.poll(if write { 4 } else { 1 }).unwrap_or(8) != 0
        } else {
            file.clone()
                .direct_byte()
                .is_none_or(|fd| fd.poll_ready(if write { 4 } else { 1 }).unwrap_or(8) != 0)
        }
    }
    pub(crate) fn native_wait_fds(&self) -> Vec<HostFd> {
        self.blocked
            .and_then(|write| {
                if write {
                    self.output.open.socket.as_ref()
                } else {
                    self.input.open.socket.as_ref()
                }
            })
            .and_then(|socket| socket.wait_sources().ok())
            .map_or_else(Vec::new, |(fds, _)| {
                fds.into_iter().map(Into::into).collect()
            })
    }
    pub(crate) fn wait_sources(&self, signal: &Arc<IoSignal>) -> io::Result<TransferWait> {
        let write = self.blocked.expect("accepted transfer wait");
        let file = if write { &self.output } else { &self.input };
        let mut wait = TransferWait {
            subscriptions: vec![],
            native: vec![],
            deadline: self.deadline,
        };
        if file.open.socket.is_some() {
            let socket = SocketOperation::from_shared(file.clone())
                .map_err(|e| io::Error::other(e.to_string()))?;
            if let Some(subscription) = socket.subscribe(signal) {
                wait.subscriptions.push(subscription);
            } else {
                wait.subscriptions
                    .extend(socket.subscribe_io_ready(signal, !write));
                let (fds, delay) = socket.wait_sources()?;
                wait.native = fds.into_iter().map(|fd| (fd.into(), false)).collect();
                if let Some(delay) = delay {
                    let deadline = Instant::now() + delay;
                    wait.deadline = Some(wait.deadline.map_or(deadline, |old| old.min(deadline)));
                }
            }
        } else if let Some(fd) = file.clone().direct_byte() {
            wait.subscriptions = fd.subscribe(signal);
        }
        Ok(wait)
    }
    pub(crate) fn execute(&mut self, v: &mut Vfs) -> Result<FileValue> {
        let source = &self.input.open;
        let dest = &self.output.open;
        if self.mode != TransferMode::Sendfile && self.flags & !15 != 0 {
            return Err(Errno(22));
        }
        if !fd_can_read(source.flags.get()) || !fd_can_write(dest.flags.get()) {
            return Err(Errno(9));
        }
        if self.mode != TransferMode::Tee && dest.flags.get() & 0x400 != 0 {
            return Err(Errno(22));
        }
        let source_pipe = source.pipe.as_ref().map(|p| p.data.clone());
        let dest_pipe = dest.pipe.as_ref().map(|p| p.data.clone());
        let from_seekable = transfer_io::Io::regular(&self.input);
        let to_seekable = transfer_io::Io::regular(&self.output);
        if Arc::ptr_eq(source, dest)
            || source_pipe
                .as_ref()
                .zip(dest_pipe.as_ref())
                .is_some_and(|(a, b)| Arc::ptr_eq(a, b))
        {
            return Err(Errno(22));
        }
        if !matches!(self.from, Ok(None)) && !from_seekable
            || !matches!(self.to, Ok(None)) && !to_seekable
        {
            return Err(Errno(29));
        }
        if self.mode != TransferMode::Sendfile && source_pipe.is_none() && dest_pipe.is_none()
            || self.mode == TransferMode::Sendfile && !from_seekable && dest_pipe.is_none()
        {
            return Err(Errno(22));
        }
        let from = self.from?;
        let to = self.to?;
        let start = if from_seekable && self.stage.is_none() {
            let pos = if let Some(pos) = self.read_from.or(from) {
                pos
            } else {
                self.io.seek(v, &Self::descriptor(&self.input), 0, 1)?
            };
            Vfs::check_io_range(pos, self.requested)?;
            pos
        } else {
            0
        };
        if to_seekable {
            let pos = to.unwrap_or_else(|| dest.file_position.snapshot());
            Vfs::check_io_range(pos, self.requested.min(Vfs::MAX_RW_COUNT))?;
        }
        let count = self.count();
        if count == 0 {
            return Ok(FileValue::Transfer {
                count: 0,
                from: from.unwrap_or(0),
                to,
            });
        }
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(Errno(11));
        }
        self.blocked = None;
        // EOF in a drained pipe never waits for space in an unrelated sink.
        if let Some(pipe) = source_pipe.as_ref().filter(|_| self.stage.is_none()) {
            let data = pipe.lock().unwrap();
            if self.mode == TransferMode::Tee
                && (data.read_reserved || data.bytes.is_empty() && data.writers != 0)
            {
                drop(data);
                self.blocked(false);
                return Err(Errno(11));
            }
            if !data.read_reserved && data.bytes.is_empty() && data.writers == 0 {
                return Ok(FileValue::Transfer {
                    count: 0,
                    from: 0,
                    to,
                });
            }
        }
        let mut destination = if self.stage.as_ref().is_some_and(|s| s.written.is_some()) {
            None
        } else if let Some(pipe) = dest_pipe {
            match WriteLease::take(pipe, count, from_seekable) {
                Ok(lease) => Some(lease),
                Err(Errno(11)) => {
                    self.blocked(true);
                    return Err(Errno(11));
                }
                Err(e) => return Err(e),
            }
        } else {
            None
        };
        let count = destination.as_ref().map_or(count, |r| r.count);
        if self.stage.is_none() {
            let input = Self::descriptor(&self.input);
            let from = start;
            self.read_from = Some(from);
            let result = if let Some(pipe) = source_pipe {
                ReadLease::take(pipe, count).map(|(lease, bytes)| Stage {
                    bytes,
                    read: Some(lease),
                    from,
                    written: None,
                })
            } else if matches!(source.control, Some(events::SharedControl::FuseFile(_))) {
                self.io
                    .call(
                        &input,
                        v,
                        FileCommand::Read {
                            count,
                            offset: Some(from),
                        },
                        transfer_io::Step::Read,
                    )
                    .and_then(transfer_io::Io::bytes)
                    .map(|bytes| Stage {
                        bytes,
                        read: None,
                        from,
                        written: None,
                    })
            } else if from_seekable {
                v.pread_description(&input, count, from).map(|bytes| Stage {
                    bytes,
                    read: None,
                    from,
                    written: None,
                })
            } else {
                v.read_description(&input, count).map(|bytes| Stage {
                    bytes,
                    read: None,
                    from,
                    written: None,
                })
            };
            match result {
                Ok(stage) => {
                    self.stage = Some(stage);
                    self.read_from = None;
                }
                Err(Errno(11)) => {
                    self.blocked(false);
                    return Err(Errno(11));
                }
                Err(e) => return Err(e),
            }
        }
        let stage = self.stage.as_mut().unwrap();
        let bytes = &stage.bytes[..stage.bytes.len().min(count)];
        let output = Self::descriptor(&self.output);
        let written = if let Some(written) = stage.written {
            Ok(written)
        } else if bytes.is_empty() {
            Ok(0)
        } else if let Some(lease) = &mut destination {
            lease.commit(bytes)
        } else if matches!(
            dest.control,
            Some(events::SharedControl::FuseFile(_) | events::SharedControl::Fuse(_))
        ) {
            self.io
                .call(
                    &output,
                    v,
                    FileCommand::Write {
                        bytes: bytes.to_vec(),
                        offset: to,
                    },
                    transfer_io::Step::Write,
                )
                .and_then(transfer_io::Io::count)
        } else if to_seekable {
            v.file_write_description(&output, bytes, to)
        } else {
            v.write_description(&output, bytes)
        };
        let n = match written {
            Ok(n) => n,
            Err(Errno(11)) if to_seekable && dest.file_position.lock().unwrap().pending != 0 => {
                let position = dest.file_position.clone();
                self.blocked(true);
                return self.io.wait_position(v, position);
            }
            Err(e) if self.io.blocked() => {
                self.blocked(true);
                return Err(e);
            }
            Err(Errno(11)) => {
                self.blocked(true);
                return Err(Errno(11));
            }
            Err(e) => return Err(e),
        };
        stage.written = Some(n);
        if self.mode != TransferMode::Tee {
            if let Some(lease) = stage.read.take() {
                lease.commit(n);
            }
        }
        if self.mode == TransferMode::Tee && n != 0 {
            if let Some(node) = &source.node {
                source.notify_file_io(node, inotify::ACCESS);
            }
            if let Some(node) = &dest.node {
                dest.notify_file_io(node, inotify::MODIFY);
            }
        }
        let position = stage.from + n as u64;
        if from_seekable && from.is_none() {
            self.io
                .seek(v, &Self::descriptor(&self.input), position as i64, 0)?;
        }
        self.stage = None;
        Ok(FileValue::Transfer {
            count: n as u64,
            from: position,
            to: to.map(|offset| offset + n as u64),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn file(v: &Vfs, fd: u32) -> SharedFd {
        v.shared_files().lookup(fd).unwrap().unwrap()
    }
    fn command(v: &Vfs, input: u32, output: u32, n: u64) -> FileWork {
        let output = file(v, output);
        FileWork::from_vfs(
            v,
            output.filesystem_target(),
            FileCommand::Transfer(Arc::new(std::sync::Mutex::new(StreamTransfer::new(
                file(v, input),
                output,
                Ok(None),
                Ok(None),
                n,
                true,
                0,
            )))),
        )
    }
    fn finish(work: FileWork) -> Result<u64> {
        match work.run() {
            FileOutcome::Complete(reply) => match reply.result? {
                FileValue::Transfer { count, .. } => Ok(count),
                _ => panic!("count"),
            },
            _ => panic!("ready transfer"),
        }
    }
    #[test]
    fn tee_duplicates_the_unread_prefix_and_never_consumes_input() {
        let mut v = Vfs::default();
        let [input, producer] = v.pipe(0).unwrap();
        let [consumer, output] = v.pipe(0).unwrap();
        assert_eq!(v.tee(u32::MAX, u32::MAX, 0, 0), Ok(0));
        assert_eq!(v.tee(u32::MAX, u32::MAX, 0, 16), Err(Errno(22)));
        v.write(producer, b"abcdef").unwrap();
        assert_eq!(v.tee(input, output, 2, 0), Ok(2));
        assert_eq!(v.read(input, 1).unwrap(), b"a");
        assert_eq!(v.tee(input, output, 20, 0), Ok(5));
        assert_eq!(v.read(consumer, 20).unwrap(), b"abbcdef");
        v.close(consumer).unwrap();
        assert_eq!(v.tee(input, output, 1, 0), Err(Errno(32)));
        assert_eq!(v.read(input, 20).unwrap(), b"bcdef");
        v.close(producer).unwrap();
        let [_reader, other_output] = v.pipe(0).unwrap();
        assert_eq!(v.tee(input, other_output, 20, 0), Ok(0));
    }
    #[test]
    fn splice_rejects_requested_overflow_before_reserving_a_pipe_prefix() {
        let mut v = Vfs::default();
        let [input, producer] = v.pipe(0).unwrap();
        v.import_file(b"/target", b"old".to_vec()).unwrap();
        let output = v.open_at(AT_FDCWD, b"/target", 2, 0).unwrap();
        v.write(producer, b"x").unwrap();
        let count = storage::MAX_TRANSFER + 8;
        let to = i64::MAX as u64 - storage::MAX_TRANSFER as u64;
        assert_eq!(
            v.splice(input, output, count, None, Some(to)),
            Err(Errno(22))
        );
        assert_eq!(v.read(input, 1).unwrap(), b"x");
        assert_eq!(v.seek(output, 0, 1), Ok(0));
        assert_eq!(v.pread(output, 3, 0).unwrap(), b"old");
    }
    #[test]
    fn reservations_preserve_prefix_capacity_and_wake_after_cancellation() {
        let mut v = Vfs::default();
        let [r, w] = v.pipe(0).unwrap();
        v.write(w, b"prefix").unwrap();
        let pipe = file(&v, r).open.pipe.as_ref().unwrap().data.clone();
        let (read, bytes) = ReadLease::take(pipe.clone(), 3).unwrap();
        assert_eq!(bytes, b"pre");
        assert_eq!(v.read(r, 2), Err(Errno(11)));
        assert_eq!(v.write(w, b"tail"), Ok(4));
        drop(read);
        assert_eq!(v.read(r, 10).unwrap(), b"prefixtail");
        let mut write = WriteLease::take(pipe.clone(), PIPE_CAPACITY - 2, false).unwrap();
        assert_eq!(v.write(w, b"abc"), Err(Errno(11)));
        assert_eq!(v.write(w, b"ab"), Ok(2));
        assert_eq!(
            write.commit(&vec![5; PIPE_CAPACITY - 2]),
            Ok(PIPE_CAPACITY - 2)
        );
        drop(write);
        assert_eq!(pipe.lock().unwrap().bytes.len(), PIPE_CAPACITY);
        assert_eq!(v.read(r, 2).unwrap(), b"ab");
        let write = WriteLease::take(pipe.clone(), 2, false).unwrap();
        drop(write);
        assert_eq!(v.write(w, b"cd"), Ok(2));
    }
    #[test]
    fn concurrent_transfers_cannot_duplicate_or_overconsume_one_prefix() {
        for _ in 0..32 {
            let mut v = Vfs::default();
            let [r, w] = v.pipe(0).unwrap();
            let [ar, aw] = v.pipe(0).unwrap();
            let [br, bw] = v.pipe(0).unwrap();
            let bytes: Vec<_> = (0..2048u32).flat_map(u32::to_le_bytes).collect();
            v.write(w, &bytes).unwrap();
            let jobs = [command(&v, r, aw, 4096), command(&v, r, bw, 4096)];
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let jobs: Vec<_> = jobs
                .into_iter()
                .map(|work| {
                    let b = barrier.clone();
                    std::thread::spawn(move || {
                        b.wait();
                        work.run()
                    })
                })
                .collect();
            // Retire both concurrent attempts before retrying a parked one;
            // its peer may still own the input reservation until it returns.
            let outcomes: Vec<_> = jobs.into_iter().map(|job| job.join().unwrap()).collect();
            for outcome in outcomes {
                match outcome {
                    FileOutcome::Waiting(work) => assert_eq!(finish(work), Ok(4096)),
                    FileOutcome::Complete(reply) => assert!(matches!(
                        reply.result,
                        Ok(FileValue::Transfer { count: 4096, .. })
                    )),
                    _ => panic!("memory transfer"),
                }
            }
            let mut all = v.read(ar, 8192).unwrap();
            all.extend(v.read(br, 8192).unwrap());
            let mut records: Vec<_> = all
                .chunks_exact(4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .collect();
            records.sort();
            assert_eq!(records, (0..2048).collect::<Vec<_>>());
            assert_eq!(v.read(r, 1), Err(Errno(11)));
        }
    }
    #[test]
    fn full_pipe_wait_has_no_input_effect_and_retains_original_resources() {
        let mut v = Vfs::default();
        let [r, w] = v.pipe(0).unwrap();
        let [out, write] = v.pipe(0).unwrap();
        v.write(w, b"keep").unwrap();
        v.write(write, &vec![1; PIPE_CAPACITY]).unwrap();
        let work = command(&v, r, write, 4);
        let FileOutcome::Waiting(work) = work.run() else {
            panic!("backpressure")
        };
        assert!(!work.ready());
        assert_eq!(v.read(r, 4).unwrap(), b"keep");
        v.write(w, b"next").unwrap();
        let original = v.dup(write, 100, false).unwrap();
        v.close(write).unwrap();
        let [reused, _] = v.pipe(0).unwrap();
        assert_eq!(reused, write);
        v.read(out, PIPE_CAPACITY).unwrap();
        assert!(work.ready());
        assert_eq!(finish(work), Ok(4));
        assert_eq!(v.read(out, 4).unwrap(), b"next");
        v.write(original, b"x").unwrap();
        assert_eq!(v.read(out, 1).unwrap(), b"x");
    }
}
