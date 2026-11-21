// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

pub(crate) struct File {
    pub(super) reference: LookupRef,
    pub(super) fh: Option<u64>,
    pub(super) flags: u32,
    pub(super) attr: std::sync::Mutex<[u8; 88]>,
    pub(super) mount: Arc<mounts::MountData>,
    pub(super) position_busy: std::sync::atomic::AtomicBool,
    pub(super) position_changed: Arc<Readiness>,
}
impl Drop for File {
    fn drop(&mut self) {
        if let Some(fh) = self.fh {
            let r = &self.reference;
            r.fs.connection.release(r.node, r.caller, fh, self.flags);
        }
    }
}

pub(super) struct Position {
    file: Arc<File>,
    offset: Arc<file_data::FilePosition>,
}
impl Drop for Position {
    fn drop(&mut self) {
        self.file.position_busy.store(false, Ordering::Release);
        self.file.position_changed.notify_atomic();
    }
}
pub(super) enum FileResult {
    Read(usize, Option<Position>),
    Write(usize, u64, Arc<File>, Option<Position>),
    Allocate(Arc<File>, Option<u64>),
    Flush(Arc<File>),
    Sync,
}

impl FileResult {
    pub(super) fn finish(&self, result: Result<Vec<u8>>) -> Result<FileValue> {
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
            Self::Read(max, pos) if bytes.len() <= *max => {
                if let Some(pos) = pos {
                    pos.offset.lock().unwrap().value += bytes.len() as u64;
                }
                Ok(FileValue::Bytes(bytes))
            }
            Self::Write(max, start, file, pos) if bytes.len() == 8 => {
                let n = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
                if n > *max {
                    return Err(Errno(5));
                }
                if n != 0 {
                    file.extend_size(start + n as u64);
                }
                if let Some(pos) = pos {
                    pos.offset.lock().unwrap().value += n as u64;
                }
                Ok(FileValue::Count(n as u64))
            }
            Self::Allocate(file, end) if bytes.is_empty() => {
                if let Some(end) = end {
                    file.extend_size(*end);
                }
                Ok(FileValue::Count(0))
            }
            Self::Sync | Self::Flush(_) if bytes.is_empty() => Ok(FileValue::Count(0)),
            _ => Err(Errno(5)),
        }
    }
}
impl File {
    pub(super) fn refresh(&self, raw: &[u8]) -> Result<()> {
        let mut attr = self.attr.lock().unwrap();
        let kind = |a: &[u8]| u32::from_le_bytes(a[60..64].try_into().unwrap()) & 0o170000;
        if kind(&attr[..]) != kind(raw) {
            return Err(Errno(5));
        }
        attr.copy_from_slice(raw);
        Ok(())
    }
    fn extend_size(&self, end: u64) {
        let mut a = self.attr.lock().unwrap();
        let size = u64::from_le_bytes(a[8..16].try_into().unwrap());
        if end > size {
            a[8..16].copy_from_slice(&end.to_le_bytes());
        }
    }
    pub(crate) fn busy(&self) -> bool {
        self.position_busy.load(Ordering::Acquire)
    }
    pub(crate) fn subscribe_position(&self, s: &Arc<IoSignal>) -> IoSubscription {
        self.position_changed.subscribe(s)
    }
    fn request(&self, v: &Vfs, opcode: u32, body: &[u8], kind: ResultKind) -> Result<Metadata> {
        let fs = &self.reference.fs;
        fs.check(&v.credentials)?;
        Ok(Metadata {
            request: Arc::new(fs.connection.request(
                opcode,
                self.reference.node,
                fs.caller(v),
                body,
            )?),
            kind,
            reference: None,
            open: None,
            mount: StatMount {
                id: self.mount.id,
                is_root: false,
            },
            dev: self.mount.device(),
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
        })
    }
    pub(crate) fn stat(self: &Arc<Self>, v: &Vfs) -> Result<Metadata> {
        let mut body = [0; 16];
        if let Some(fh) = self.fh {
            body[..4].copy_from_slice(&1u32.to_le_bytes());
            body[8..].copy_from_slice(&fh.to_le_bytes());
        }
        self.request(v, 3, &body, ResultKind::FileStat(self.clone()))
    }
    pub(crate) fn cached_stat(&self, v: &Vfs) -> Result<([u8; 128], StatMount)> {
        self.reference.fs.check(&v.credentials)?;
        Ok((
            attribute_stat(
                &self.attr.lock().unwrap()[..],
                self.mount.device(),
                &self.reference.fs.namespace,
                &v.credentials.user_namespace,
            )?,
            StatMount {
                id: self.mount.id,
                is_root: false,
            },
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
        let Some(fh) = self.fh else {
            return;
        };
        let r = &self.reference;
        if r.fs.flush_unsupported.load(Ordering::Relaxed) {
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
        if self.reference.fs.flush_unsupported.load(Ordering::Relaxed) {
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
        position: &Arc<file_data::FilePosition>,
    ) -> Result<Option<Metadata>> {
        if matches!(command, FileCommand::Stat) {
            return self.stat(v).map(Some);
        }
        let fh = self.fh.ok_or(Errno(9))?;
        let (opcode, body, kind) = match command {
            FileCommand::Read { offset, .. } | FileCommand::Write { offset, .. } => {
                let write = matches!(command, FileCommand::Write { .. });
                if write && !fd_can_write(self.flags) || !write && !fd_can_read(self.flags) {
                    return Err(Errno(9));
                }
                let mut lease = None;
                let start = if let Some(off) = offset {
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
                        file: self.clone(),
                        offset: position.clone(),
                    });
                    position.snapshot()
                };
                let len = match command {
                    FileCommand::Read { count, .. } => *count,
                    FileCommand::Write { bytes, .. } => bytes.len(),
                    _ => unreachable!(),
                }
                .min(4096);
                if start > i64::MAX as u64 || (len as u64) > i64::MAX as u64 - start {
                    return Err(Errno(22));
                }
                let mut body = vec![0; 40];
                body[..8].copy_from_slice(&fh.to_le_bytes());
                body[8..16].copy_from_slice(&start.to_le_bytes());
                body[16..20].copy_from_slice(&(len as u32).to_le_bytes());
                body[32..36].copy_from_slice(&self.flags.to_le_bytes());
                if let FileCommand::Write { bytes, .. } = command {
                    if self.mount.readonly() {
                        return Err(Errno(30));
                    }
                    if start + len as u64 > v.file_size_limit.get() {
                        return Err(Errno(27));
                    }
                    body.extend_from_slice(&bytes[..len]);
                    (16, body, FileResult::Write(len, start, self.clone(), lease))
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
                if self.mount.readonly() {
                    return Err(Errno(30));
                }
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
                    FileResult::Allocate(self.clone(), (*mode == 0).then_some(end)),
                )
            }
            FileCommand::Sync { data_only } => {
                let mut body = vec![0; 16];
                body[..8].copy_from_slice(&fh.to_le_bytes());
                body[8] = u8::from(*data_only);
                (20, body, FileResult::Sync)
            }
            _ => return Err(Errno(95)),
        };
        self.request(v, opcode, &body, ResultKind::File(kind))
            .map(Some)
    }
}
