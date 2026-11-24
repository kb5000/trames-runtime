// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

pub(crate) struct File {
    pub(super) reference: LookupRef,
    pub(super) _usage: Option<Arc<ConnectionUse>>,
    pub(super) fh: Option<u64>,
    pub(super) flags: u32,
    pub(super) status: OnceLock<fd_status::StatusFlags>,
    pub(super) open_flags: u32,
    pub(super) directory: bool,
    pub(super) attr: Arc<inode::Attr>,
    pub(super) mount: Arc<mounts::MountData>,
    pub(super) position_busy: std::sync::atomic::AtomicBool,
    pub(super) position_changed: Arc<Readiness>,
}
impl Drop for File {
    fn drop(&mut self) {
        if let Some(fh) = self.fh {
            let r = &self.reference;
            r.fs.connection
                .release(r.node, r.caller, fh, self.current_flags(), self.directory);
        }
    }
}

pub(super) struct Position {
    original: SharedFd,
    offset: Arc<file_data::FilePosition>,
    // Nonempty synchronized writes have end > 0. Zero means no deferred f_pos.
    pending: u64,
}
impl crate::read_reply::CommitRead for Position {
    fn commit(&self, copied: usize) {
        self.offset.lock().unwrap().value += copied as u64;
    }
}
impl Drop for Position {
    fn drop(&mut self) {
        let Some(events::SharedControl::FuseFile(file)) = &self.original.open.control else {
            unreachable!("a FUSE position retains its original OFD")
        };
        file.position_busy.store(false, Ordering::Release);
        file.position_changed.notify_atomic();
    }
}
pub(super) enum FileResult {
    Read(usize, Option<Position>),
    Write {
        max: usize,
        start: u64,
        file: Arc<File>,
        position: Option<Position>,
        sync: Option<bool>,
        _writer: Option<mapped::MountWrite>,
        _transaction: inode::Write,
    },
    Allocate {
        file: Arc<File>,
        end: Option<u64>,
        offset: u64,
        length: u64,
        _writer: mapped::MountWrite,
        _transaction: inode::Write,
    },
    Flush(Arc<File>),
    Sync {
        file: Arc<File>,
        count: u64,
        _position: Option<Position>,
        _writer: Option<mapped::MountWrite>,
    },
    Directory(usize, usize, Option<Position>),
}

/// A daemon reply retains the OFD's offset transaction until guest copy-out.
/// A fault after a complete entry commits only that entry's opaque cookie.
pub struct DirectoryReply {
    bytes: Vec<u8>,
    capacity: usize,
    position: Position,
    consumed: usize,
    copied: usize,
}
impl DirectoryReply {
    pub fn copied(&self) -> usize {
        self.copied
    }
    /// Decode one record without advancing the accepted OFD. A caller may
    /// retain this record across asynchronous guest page faults.
    pub fn next_entry(&self) -> Result<Option<Vec<u8>>> {
        let input = &self.bytes[self.consumed..];
        if input.len() < 24 {
            return Ok(None);
        }
        let name_len = u32::from_le_bytes(input[16..20].try_into().unwrap()) as usize;
        if name_len == 0 || name_len > 255 {
            return Err(Errno(5));
        }
        let wire_len = (24 + name_len + 7) & !7;
        if wire_len > input.len() {
            return Ok(None);
        }
        let name = &input[24..24 + name_len];
        if name.contains(&b'/') {
            return Err(Errno(5));
        }
        let record_len = (19 + name_len + 1 + 7) & !7;
        if record_len > self.capacity - self.copied {
            return Err(Errno(22));
        }
        let mut record = vec![0; record_len];
        record[..16].copy_from_slice(&input[..16]);
        record[16..18].copy_from_slice(&(record_len as u16).to_le_bytes());
        record[18] = input[20];
        record[19..19 + name_len].copy_from_slice(name);
        Ok(Some(record))
    }
    /// Commit only after every fragment of the current record was copied.
    pub fn commit_entry(&mut self) {
        let input = &self.bytes[self.consumed..];
        let name_len = u32::from_le_bytes(input[16..20].try_into().unwrap()) as usize;
        let cookie = u64::from_le_bytes(input[8..16].try_into().unwrap());
        self.position.offset.lock().unwrap().value = cookie;
        self.consumed += (24 + name_len + 7) & !7;
        self.copied += (19 + name_len + 1 + 7) & !7;
    }
    pub fn copy_to(mut self, mut copy: impl FnMut(usize, &[u8]) -> Result<()>) -> Result<u64> {
        loop {
            let entry = self.next_entry().and_then(|entry| {
                if let Some(record) = &entry {
                    copy(self.copied, record)?;
                }
                Ok(entry)
            });
            match entry {
                Ok(Some(_)) => self.commit_entry(),
                Ok(None) => return Ok(self.copied as u64),
                Err(error) => {
                    return if self.copied == 0 {
                        Err(error)
                    } else {
                        Ok(self.copied as u64)
                    }
                }
            }
        }
    }
}

impl FileResult {
    pub(super) fn local_reply(&mut self) -> Result<FileValue> {
        self.finish(Ok(if matches!(self, Self::Write { .. }) {
            vec![0; 8]
        } else {
            Vec::new()
        }))
    }
    pub(super) fn after_write_sync(&self) -> Option<(Arc<File>, bool)> {
        match self {
            Self::Write {
                file,
                sync: Some(data_only),
                ..
            } => Some((file.clone(), *data_only)),
            _ => None,
        }
    }
    pub(super) fn take_sync_leases(&mut self) -> (Option<Position>, Option<mapped::MountWrite>) {
        match self {
            Self::Write {
                position, _writer, ..
            } => (position.take(), _writer.take()),
            _ => unreachable!("only a completed write can continue with sync"),
        }
    }
    pub(super) fn finish(&mut self, result: Result<Vec<u8>>) -> Result<FileValue> {
        if let Self::Sync {
            file,
            count,
            _position: position,
            ..
        } = self
        {
            match result {
                Err(Errno(38)) => {
                    file.reference
                        .fs
                        .sync_unsupported
                        .fetch_or(if file.directory { 2 } else { 1 }, Ordering::Relaxed);
                }
                Ok(bytes) if bytes.is_empty() => {}
                Ok(_) => return Err(Errno(5)),
                Err(error) => return Err(error),
            }
            if let Some(position) = position {
                let end = std::mem::take(&mut position.pending);
                if end != 0 {
                    position.offset.lock().unwrap().value = end;
                }
            }
            return Ok(FileValue::Count(*count));
        }
        if let Self::Flush(file) = self {
            if matches!(result, Err(Errno(38))) {
                file.reference
                    .fs
                    .flush_unsupported
                    .store(true, Ordering::Relaxed);
                return Ok(FileValue::Count(0));
            }
        }
        let bytes = result?;
        match self {
            Self::Directory(max, capacity, position) if bytes.len() <= *max => {
                Ok(FileValue::Directory(DirectoryReply {
                    bytes,
                    capacity: *capacity,
                    position: position.take().expect("directory offset transaction"),
                    consumed: 0,
                    copied: 0,
                }))
            }
            Self::Read(max, pos) if bytes.len() <= *max => Ok(match pos.take() {
                Some(position) => FileValue::Read(ReadReply::new(bytes, position)),
                None => FileValue::Bytes(bytes),
            }),
            Self::Write {
                max,
                start,
                file,
                position: pos,
                sync,
                ..
            } if bytes.len() == 8 => {
                let n = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
                if n > *max {
                    return Err(Errno(5));
                }
                if n != 0 {
                    file.extend_size(*start + n as u64);
                    file.attr.cache.invalidate(*start, n as u64);
                }
                if let Some(pos) = pos {
                    let end = *start + n as u64;
                    if sync.is_some() && n != 0 {
                        pos.pending = end;
                    } else {
                        pos.offset.lock().unwrap().value = end;
                    }
                }
                Ok(FileValue::Count(n as u64))
            }
            Self::Allocate {
                file,
                end,
                offset,
                length,
                ..
            } if bytes.is_empty() => {
                if let Some(end) = end {
                    file.extend_size(*end);
                } else {
                    file.extend_size(0);
                }
                file.attr.cache.invalidate(*offset, *length);
                Ok(FileValue::Count(0))
            }
            Self::Flush(_) if bytes.is_empty() => Ok(FileValue::Count(0)),
            _ => Err(Errno(5)),
        }
    }
}
impl File {
    pub(super) fn current_flags(&self) -> u32 {
        self.status
            .get()
            .map_or(self.flags, fd_status::StatusFlags::get)
    }
    fn stream(&self) -> bool {
        !self.directory && self.open_flags & 16 != 0
    }
    fn nonseekable(&self) -> bool {
        !self.directory && self.open_flags & (4 | 16) != 0
    }
    pub(crate) fn waiting_for(&self, command: &FileCommand) -> bool {
        let position = matches!(
            command,
            FileCommand::Seek { .. } | FileCommand::ReadDirectory { .. }
        ) || !self.stream()
            && matches!(
                command,
                FileCommand::Read { offset: None, .. }
                    | FileCommand::Write { offset: None, .. }
                    | FileCommand::WriteSync { offset: None, .. }
            );
        let data = matches!(
            command,
            FileCommand::Write { .. }
                | FileCommand::WriteSync { .. }
                | FileCommand::Allocate { .. }
        );
        position && self.busy() || data && self.attr.writing()
    }
    pub(crate) fn subscribe_operation(
        &self,
        command: &FileCommand,
        signal: &Arc<IoSignal>,
    ) -> Vec<IoSubscription> {
        let mut subscriptions = vec![self.subscribe_position(signal)];
        if matches!(
            command,
            FileCommand::Write { .. }
                | FileCommand::WriteSync { .. }
                | FileCommand::Allocate { .. }
        ) {
            subscriptions.push(self.attr.subscribe_write(signal));
        }
        subscriptions
    }
    fn extend_size(&self, end: u64) {
        let mut a = self.attr.lock().unwrap();
        a.version = self.reference.fs.connection.next_attr_version();
        let size = u64::from_le_bytes(a[8..16].try_into().unwrap());
        if end > size {
            a[8..16].copy_from_slice(&end.to_le_bytes());
        }
        self.attr.validity.set(0, 0);
    }
    pub(crate) fn busy(&self) -> bool {
        self.position_busy.load(Ordering::Acquire)
    }
    pub(crate) fn subscribe_position(&self, s: &Arc<IoSignal>) -> IoSubscription {
        self.position_changed.subscribe(s)
    }
    pub(super) fn request(
        &self,
        v: &Vfs,
        opcode: u32,
        body: &[u8],
        kind: ResultKind,
    ) -> Result<Metadata> {
        self.attr.check()?;
        let fs = &self.reference.fs;
        fs.check(&v.credentials)?;
        Ok(Metadata {
            request: if matches!(opcode, 15 | 16)
                && body.get(16..20).is_some_and(|bytes| bytes == [0; 4])
                || matches!(opcode, 20 | 30)
                    && fs.sync_unsupported.load(Ordering::Relaxed)
                        & (if opcode == 30 { 2 } else { 1 })
                        != 0
            {
                None
            } else {
                Some(Arc::new(fs.connection.request(
                    opcode,
                    self.reference.node,
                    fs.caller(v),
                    body,
                )?))
            },
            kind,
            _usage: None,
            resolved: None,
            resolved_entry: None,
            reference: None,
            open: None,
            mount: StatMount::mounted(
                self.mount.id,
                self.inode()
                    .is_some_and(|n| Arc::ptr_eq(&n, &self.mount.root)),
            ),
            dev: self.mount.device(),
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
        })
    }
    pub(super) fn sync(
        self: &Arc<Self>,
        v: &Vfs,
        data_only: bool,
        count: u64,
        position: Option<Position>,
        writer: Option<mapped::MountWrite>,
    ) -> Result<Metadata> {
        let mut body = [0; 16];
        body[..8].copy_from_slice(&self.fh.ok_or(Errno(9))?.to_le_bytes());
        body[8] = u8::from(data_only);
        self.request(
            v,
            if self.directory { 30 } else { 20 },
            &body,
            ResultKind::File(FileResult::Sync {
                file: self.clone(),
                count,
                _position: position,
                _writer: writer,
            }),
        )
    }
    pub(crate) fn stat(self: &Arc<Self>, v: &Vfs) -> Result<Metadata> {
        if let Some(node) = self.inode() {
            self.reference.fs.invalidate_acl(&node);
        }
        let mut body = [0; 16];
        if let Some(fh) = self.fh {
            body[..4].copy_from_slice(&1u32.to_le_bytes());
            body[8..].copy_from_slice(&fh.to_le_bytes());
        }
        self.request(v, 3, &body, ResultKind::FileStat(self.clone()))
    }
    pub(crate) fn cached_stat(&self, v: &Vfs) -> Result<([u8; 128], StatMount)> {
        self.reference.fs.check(&v.credentials)?;
        self.attr.check()?;
        Ok((
            attribute_stat(
                &self.attr.lock().unwrap()[..],
                self.mount.device(),
                &self.reference.fs.namespace,
                &v.credentials.user_namespace,
            )?,
            StatMount::mounted(
                self.mount.id,
                self.inode()
                    .is_some_and(|n| Arc::ptr_eq(&n, &self.mount.root)),
            ),
        ))
    }
    pub(crate) fn disable_flush(&self) {
        self.reference
            .fs
            .flush_unsupported
            .store(true, Ordering::Relaxed);
    }
    // Implicit closes cannot return a daemon error. Keep the open file until
    // FLUSH has completed so RELEASE cannot overtake it.
    pub(crate) fn flush_implicit(self: &Arc<Self>, owner: u32) {
        if self.attr.check().is_err() {
            return;
        }
        let Some(fh) = self.fh else {
            return;
        };
        let r = &self.reference;
        if self.directory
            || self.open_flags & 32 != 0
            || r.fs.flush_unsupported.load(Ordering::Relaxed)
        {
            return;
        }
        let mut body = [0; 24];
        body[..8].copy_from_slice(&fh.to_le_bytes());
        body[16..24].copy_from_slice(&u64::from(owner).to_le_bytes());
        r.fs.connection
            .background(25, r.node, r.caller, &body, Some(self.clone()));
    }
    pub(crate) fn flush(self: &Arc<Self>, v: &Vfs) -> Result<Option<Metadata>> {
        let Some(fh) = self.fh else { return Ok(None) };
        if self.directory
            || self.open_flags & 32 != 0
            || self.reference.fs.flush_unsupported.load(Ordering::Relaxed)
        {
            return Ok(None);
        }
        let mut body = [0; 24];
        body[..8].copy_from_slice(&fh.to_le_bytes());
        body[16..24].copy_from_slice(&u64::from(v.lock_owner).to_le_bytes());
        self.request(
            v,
            25,
            &body,
            ResultKind::File(FileResult::Flush(self.clone())),
        )
        .map(Some)
    }
    pub(crate) fn operation(
        self: &Arc<Self>,
        v: &Vfs,
        command: &FileCommand,
        original: &SharedFd,
    ) -> Result<Option<Metadata>> {
        let position = &original.open.file_position;
        self.attr.check()?;
        if matches!(command, FileCommand::Stat) {
            return self.stat(v).map(Some);
        }
        if let FileCommand::Truncate(length) = command {
            return Metadata::file_size(v, self.clone(), *length, false).map(Some);
        }
        let fh = self.fh.ok_or(Errno(9))?;
        let flags = self.current_flags();
        let (opcode, body, kind) = match command {
            FileCommand::ReadDirectory { count } => {
                if !self.directory {
                    return Err(Errno(20));
                }
                if !fd_can_read(self.flags) {
                    return Err(Errno(9));
                }
                if *count > i32::MAX as usize {
                    return Err(Errno(22));
                }
                if self
                    .position_busy
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
                {
                    return Ok(None);
                }
                let lease = Position {
                    original: original.clone(),
                    offset: position.clone(),
                    pending: 0,
                };
                // Uncached Linux READDIR asks for one page independently of
                // the caller's getdents buffer; cookies commit during copy-out.
                let mut body = vec![0; 40];
                body[..8].copy_from_slice(&fh.to_le_bytes());
                body[8..16].copy_from_slice(&position.snapshot().to_le_bytes());
                body[16..20].copy_from_slice(&4096u32.to_le_bytes());
                body[32..36].copy_from_slice(&flags.to_le_bytes());
                (28, body, FileResult::Directory(4096, *count, Some(lease)))
            }
            FileCommand::Read { offset, .. }
            | FileCommand::Write { offset, .. }
            | FileCommand::WriteSync { offset, .. } => {
                if self.directory {
                    return Err(Errno(21));
                }
                let write = matches!(
                    command,
                    FileCommand::Write { .. } | FileCommand::WriteSync { .. }
                );
                if write && !fd_can_write(self.flags) || !write && !fd_can_read(self.flags) {
                    return Err(Errno(9));
                }
                if offset.is_some() && self.nonseekable() {
                    return Err(Errno(29));
                }
                let transaction = if write {
                    let Some(transaction) = self.attr.try_write() else {
                        return Ok(None);
                    };
                    Some(transaction)
                } else {
                    None
                };
                let mut lease = None;
                let mut start = if self.stream() {
                    0
                } else if let Some(off) = offset {
                    *off
                } else {
                    if self
                        .position_busy
                        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                        .is_err()
                    {
                        return Ok(None);
                    }
                    lease = Some(Position {
                        original: original.clone(),
                        offset: position.clone(),
                        pending: 0,
                    });
                    position.snapshot()
                };
                let mut len = match command {
                    FileCommand::Read { count, .. } => *count,
                    FileCommand::Write { bytes, .. } | FileCommand::WriteSync { bytes, .. } => {
                        bytes.len()
                    }
                    _ => unreachable!(),
                }
                .min(self.reference.fs.connection.data_limit());
                if start > i64::MAX as u64 || (len as u64) > i64::MAX as u64 - start {
                    return Err(Errno(22));
                }
                if write && flags & 0x400 != 0 {
                    start =
                        u64::from_le_bytes(self.attr.lock().unwrap()[8..16].try_into().unwrap());
                }
                if write && len != 0 {
                    let limit = v.file_size_limit.get();
                    if start >= limit {
                        v.file_size_signal.set(true);
                        return Err(Errno(27));
                    }
                    if start >= i64::MAX as u64 {
                        return Err(Errno(27));
                    }
                    len = len.min((limit - start) as usize);
                    len = len.min((i64::MAX as u64 - start) as usize);
                }
                let mut body = vec![0; 40];
                body[..8].copy_from_slice(&fh.to_le_bytes());
                body[8..16].copy_from_slice(&start.to_le_bytes());
                body[16..20].copy_from_slice(&(len as u32).to_le_bytes());
                body[32..36].copy_from_slice(&flags.to_le_bytes());
                if let FileCommand::Write { bytes, .. } | FileCommand::WriteSync { bytes, .. } =
                    command
                {
                    let writer = mapped::MountWrite::new(&self.mount.identity)?;
                    body.extend_from_slice(&bytes[..len]);
                    (
                        16,
                        body,
                        FileResult::Write {
                            max: len,
                            start,
                            file: self.clone(),
                            position: lease,
                            sync: fd_status::write_sync(
                                flags,
                                if let FileCommand::WriteSync { data_only, .. } = command {
                                    Some(*data_only)
                                } else {
                                    None
                                },
                            ),
                            _writer: Some(writer),
                            _transaction: transaction.unwrap(),
                        },
                    )
                } else {
                    (15, body, FileResult::Read(len, lease))
                }
            }
            FileCommand::Allocate {
                mode,
                offset,
                length,
            } => {
                if !fd_can_write(self.flags) {
                    return Err(Errno(9));
                }
                let writer = mapped::MountWrite::new(&self.mount.identity)?;
                let Some(transaction) = self.attr.try_write() else {
                    return Ok(None);
                };
                let end = offset
                    .checked_add(*length)
                    .filter(|e| *e <= i64::MAX as u64)
                    .ok_or(Errno(27))?;
                if *length == 0 {
                    return Err(Errno(22));
                }
                if *mode > 1 {
                    return Err(Errno(95));
                }
                if *mode == 0 && end > v.file_size_limit.get() {
                    return Err(Errno(27));
                }
                let mut body = vec![0; 32];
                body[..8].copy_from_slice(&fh.to_le_bytes());
                body[8..16].copy_from_slice(&offset.to_le_bytes());
                body[16..24].copy_from_slice(&length.to_le_bytes());
                body[24..28].copy_from_slice(&(*mode as u32).to_le_bytes());
                (
                    43,
                    body,
                    FileResult::Allocate {
                        file: self.clone(),
                        end: (*mode == 0).then_some(end),
                        offset: *offset,
                        length: *length,
                        _writer: writer,
                        _transaction: transaction,
                    },
                )
            }
            FileCommand::Sync { data_only } => {
                return self.sync(v, *data_only, 0, None, None).map(Some);
            }
            _ => return Err(Errno(95)),
        };
        if (matches!(&kind, FileResult::Write { max, .. } if *max != 0)
            || matches!(&kind, FileResult::Allocate { .. }))
            && self
                .inode()
                .is_some_and(|node| node.borrow().mode & 0o170000 == 0o100000)
        {
            return self.prepare_data_write(v, opcode, body, kind).map(Some);
        }
        self.request(v, opcode, &body, ResultKind::File(kind))
            .map(Some)
    }
    pub(crate) fn seek(
        &self,
        position: &file_data::FilePosition,
        offset: i64,
        whence: u32,
    ) -> Result<Option<u64>> {
        if self.fh.is_none() {
            return Err(Errno(9));
        }
        if self.nonseekable() {
            return Err(Errno(29));
        }
        if self
            .position_busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Ok(None);
        }
        let result = (|| {
            let mut pos = position.lock().unwrap();
            let base = match whence {
                0 => 0,
                1 => pos.value,
                2 => u64::from_le_bytes(self.attr.lock().unwrap()[8..16].try_into().unwrap()),
                _ => return Err(Errno(22)),
            };
            let value = (base as i128 + offset as i128)
                .try_into()
                .ok()
                .filter(|v: &u64| *v <= i64::MAX as u64)
                .ok_or(Errno(22))?;
            pos.value = value;
            Ok(Some(value))
        })();
        self.position_busy.store(false, Ordering::Release);
        self.position_changed.notify_atomic();
        result
    }
}
