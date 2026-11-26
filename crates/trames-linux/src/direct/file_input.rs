// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only ABI import. Successful fragments and the original OFD survive a
//! page wait; no filesystem/descriptor operation has executed at this point.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use trames_memory::{MemoryError, PageFault, PAGE_SIZE};

#[derive(Default)]
pub(crate) struct Bytes {
    fragments: RefCell<BTreeMap<(u64, usize), Vec<u8>>>,
    checked: RefCell<BTreeSet<(u64, usize, u8)>>,
}
pub(crate) struct Reader<'a, M> {
    memory: &'a M,
    bytes: &'a Bytes,
    fault: RefCell<Option<PageFault>>,
}
impl<'a, M: CpuMemory> Reader<'a, M> {
    pub(crate) fn new(memory: &'a M, bytes: &'a Bytes) -> Self {
        Self {
            memory,
            bytes,
            fault: RefCell::default(),
        }
    }
    pub(crate) fn fault(&self) -> Option<PageFault> {
        self.fault.borrow_mut().take()
    }
    fn observe<T>(&self, result: Result<T, MemoryError>) -> Result<T, MemoryError> {
        if let Err(MemoryError::Pending(fault)) = &result {
            *self.fault.borrow_mut() = Some(fault.clone());
        }
        result
    }
}
impl<M: CpuMemory> CpuMemory for Reader<'_, M> {
    fn async_faults_possible(&self) -> bool {
        self.memory.async_faults_possible()
    }
    fn mapped_at_or_after(&self, address: u64) -> bool {
        self.memory.mapped_at_or_after(address)
    }
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryError> {
        let mut done = 0;
        while done < output.len() {
            let address = address
                .checked_add(done as u64)
                .ok_or(MemoryError::InvalidRange)?;
            let n = (output.len() - done).min((PAGE_SIZE - address % PAGE_SIZE) as usize);
            let key = (address, n);
            let cached = self.bytes.fragments.borrow().get(&key).cloned();
            if let Some(bytes) = cached {
                output[done..done + n].copy_from_slice(&bytes);
            } else {
                self.observe(self.memory.read(address, &mut output[done..done + n]))?;
                self.bytes
                    .fragments
                    .borrow_mut()
                    .insert(key, output[done..done + n].to_vec());
            }
            done += n;
        }
        Ok(())
    }
    fn check(&self, address: u64, len: usize, access: Access) -> Result<(), MemoryError> {
        let kind = match access {
            Access::Read => 0,
            Access::Write => 1,
            Access::Execute => 2,
        };
        let key = (address, len, kind);
        if self.bytes.checked.borrow().contains(&key) {
            return Ok(());
        }
        self.observe(self.memory.check(address, len, access))?;
        self.bytes.checked.borrow_mut().insert(key);
        Ok(())
    }
    fn check_translation(&self, address: u64) -> Result<(), MemoryError> {
        self.observe(self.memory.check_translation(address))
    }
    fn fetch_u32(&self, address: u64) -> Result<u32, MemoryError> {
        self.observe(self.memory.fetch_u32(address))
    }
    fn instruction_identity(&self) -> (u64, u64, u64) {
        self.memory.instruction_identity()
    }
    fn instruction_page_identity(&self, address: u64) -> Result<(u64, u64, u64), MemoryError> {
        self.memory.instruction_page_identity(address)
    }
    fn write(&mut self, _: u64, _: &[u8]) -> Result<(), MemoryError> {
        unreachable!("read-only ABI import")
    }
    fn atomic_update<T>(
        &mut self,
        _: u64,
        _: usize,
        _: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError> {
        unreachable!("read-only ABI import")
    }
    fn exclusive_read(&mut self, _: u64, _: &mut [u8]) -> Result<u128, MemoryError> {
        unreachable!("read-only ABI import")
    }
    fn exclusive_write(&mut self, _: u64, _: &[u8], _: Option<u128>) -> Result<bool, MemoryError> {
        unreachable!("read-only ABI import")
    }
}
/// Scalar control ABIs finish importing before their one provider operation.
/// Capture its outputs once; real user copies then have an independent cursor.
pub(super) struct Capture<'a, M> {
    pub(super) reader: Reader<'a, M>,
    pub(super) outputs: &'a mut crate::copy_replay::Replay,
}
/// Structural registration imports bytes through the same journal, while pin
/// authority remains on the actual admitted mm. Outputs are staged separately.
pub(super) struct RegistrationMemory<'a, M> {
    pub(super) memory: &'a mut M,
    pub(super) bytes: &'a Bytes,
    pub(super) outputs: &'a mut crate::copy_replay::Replay,
    pub(super) fault: RefCell<Option<PageFault>>,
}
impl<M: CpuMemory> RegistrationMemory<'_, M> {
    fn observe<T>(&self, result: Result<T, MemoryError>) -> Result<T, MemoryError> {
        if let Err(MemoryError::Pending(fault)) = &result {
            *self.fault.borrow_mut() = Some(fault.clone());
        }
        result
    }
}
impl<M: CpuMemory> CpuMemory for RegistrationMemory<'_, M> {
    fn async_faults_possible(&self) -> bool {
        self.memory.async_faults_possible()
    }
    fn mapped_at_or_after(&self, address: u64) -> bool {
        self.memory.mapped_at_or_after(address)
    }
    fn read(&self, address: u64, out: &mut [u8]) -> Result<(), MemoryError> {
        self.observe(Reader::new(self.memory, self.bytes).read(address, out))
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.outputs.capture(address, bytes);
        Ok(())
    }
    fn check(&self, address: u64, len: usize, access: Access) -> Result<(), MemoryError> {
        self.observe(Reader::new(self.memory, self.bytes).check(address, len, access))
    }
    fn check_translation(&self, address: u64) -> Result<(), MemoryError> {
        self.observe(self.memory.check_translation(address))
    }
    fn fetch_u32(&self, address: u64) -> Result<u32, MemoryError> {
        self.observe(self.memory.fetch_u32(address))
    }
    fn instruction_identity(&self) -> (u64, u64, u64) {
        self.memory.instruction_identity()
    }
    fn instruction_page_identity(&self, address: u64) -> Result<(u64, u64, u64), MemoryError> {
        self.memory.instruction_page_identity(address)
    }
    fn pin_buffer_rw(
        &mut self,
        address: u64,
        length: usize,
    ) -> Option<Result<trames_memory::PinnedBuffer, MemoryError>> {
        let result = self.memory.pin_buffer_rw(address, length)?;
        Some(self.observe(result))
    }
    fn atomic_update<T>(
        &mut self,
        _: u64,
        _: usize,
        _: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError> {
        unreachable!("registration ABI")
    }
    fn exclusive_read(&mut self, _: u64, _: &mut [u8]) -> Result<u128, MemoryError> {
        unreachable!("registration ABI")
    }
    fn exclusive_write(&mut self, _: u64, _: &[u8], _: Option<u128>) -> Result<bool, MemoryError> {
        unreachable!("registration ABI")
    }
}
impl<M: CpuMemory> CpuMemory for Capture<'_, M> {
    fn async_faults_possible(&self) -> bool {
        self.reader.async_faults_possible()
    }
    fn mapped_at_or_after(&self, address: u64) -> bool {
        self.reader.mapped_at_or_after(address)
    }
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryError> {
        self.reader.read(address, output)
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.outputs.capture(address, bytes);
        Ok(())
    }
    fn check(&self, address: u64, len: usize, access: Access) -> Result<(), MemoryError> {
        self.reader.check(address, len, access)
    }
    fn check_translation(&self, address: u64) -> Result<(), MemoryError> {
        self.reader.check_translation(address)
    }
    fn fetch_u32(&self, address: u64) -> Result<u32, MemoryError> {
        self.reader.fetch_u32(address)
    }
    fn instruction_identity(&self) -> (u64, u64, u64) {
        self.reader.instruction_identity()
    }
    fn instruction_page_identity(&self, address: u64) -> Result<(u64, u64, u64), MemoryError> {
        self.reader.instruction_page_identity(address)
    }
    fn atomic_update<T>(
        &mut self,
        _: u64,
        _: usize,
        _: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError> {
        unreachable!("scalar control output")
    }
    fn exclusive_read(&mut self, _: u64, _: &mut [u8]) -> Result<u128, MemoryError> {
        unreachable!("scalar control output")
    }
    fn exclusive_write(&mut self, _: u64, _: &[u8], _: Option<u128>) -> Result<bool, MemoryError> {
        unreachable!("scalar control output")
    }
}
pub(super) struct Input {
    pub(super) paths: trames_vfs::PathQueries,
    pub(super) file: trames_vfs::FileTarget,
    pub(super) regular: bool,
    pub(super) unsigned: bool,
    pub(super) bytes: Bytes,
}
pub(super) enum Accepted {
    File(Input),
    Path(PathInput),
    Byte(RetainedByte),
    Socket(RetainedSocket),
    EventWait(Arc<crate::RetainedWait>),
    WaitInput(Box<super::event_input::WaitInput>),
    EpollControl(Bytes),
    EpollControlWait(Box<trames_vfs::EpollControl>),
    Pair(Pair),
    Registration(Box<uring::Registration>),
    UringSetup(Box<uring::Setup>),
    UringEnter(Box<uring::EnterInput>),
    AioLookup(Box<aio::lookup::Lookup>),
    AioSetup(Box<aio::SetupInput>),
    Uts(Box<super::metadata::UtsInput>),
    TimerFd(Box<super::timer_control::TimerControl>),
    Ioctl(Box<super::ioctl_control::IoctlControl>),
}
impl Accepted {
    pub(super) fn file(&self) -> Option<trames_vfs::FileTarget> {
        match self {
            Self::File(input) => Some(input.file.clone()),
            Self::Path(_) => None,
            Self::Byte(file) => file.fd.shared_file().map(|file| file.filesystem_target()),
            Self::Socket(_)
            | Self::EventWait(_)
            | Self::WaitInput(_)
            | Self::EpollControl(_)
            | Self::EpollControlWait(_)
            | Self::Pair(_)
            | Self::Registration(_)
            | Self::UringSetup(_)
            | Self::UringEnter(_)
            | Self::AioLookup(_)
            | Self::AioSetup(_)
            | Self::Uts(_)
            | Self::TimerFd(_)
            | Self::Ioctl(_) => None,
        }
    }
}
pub(super) struct Pair {
    pair: Option<trames_vfs::PreparedPair>,
    copy: file::FileCopyout,
}
impl Pair {
    pub(super) fn new(pair: trames_vfs::PreparedPair, address: u64) -> Self {
        let bytes = pair
            .numbers()
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let copy = file::FileCopyout::new(
            &file::FileOutput::Buffer {
                address,
                capacity: 8,
                query_size: false,
                zero: false,
            },
            Ok(trames_vfs::FileValue::Bytes(bytes)),
        );
        Self {
            pair: Some(pair),
            copy,
        }
    }
    pub(super) fn progress(
        &mut self,
        memory: &mut impl CpuMemory,
    ) -> Result<Result<u64, Errno>, PageFault> {
        Ok(self
            .copy
            .progress(memory)?
            .and_then(|_| self.pair.take().unwrap().publish().map(|_| 0)))
    }
}
pub(super) struct ByteInput {
    pub(super) original: RetainedByte,
    bytes: Bytes,
    pub(super) fault: Option<PageFault>,
    pub(super) deadline: Option<Instant>,
}
impl ByteInput {
    pub(super) fn new(original: RetainedByte, number: u32) -> Self {
        let deadline = original.socket_deadline(number);
        Self {
            original,
            bytes: Bytes::default(),
            fault: None,
            deadline,
        }
    }
    pub(super) fn attempt(
        &mut self,
        direct: &DirectSyscalls,
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
        _original_paths: Option<&trames_vfs::Vfs>,
    ) -> Option<Result<u64, Errno>> {
        let mut reader = Reader::new(memory, &self.bytes);
        let file = &mut self.original;
        let prepared = (|| {
            if matches!(file.operation, ByteOperation::Plain)
                && StreamWrite::accepts(&file.fd, number, args)
            {
                file.operation = ByteOperation::Stream(Arc::new(StreamWrite::new(
                    number,
                    args,
                    &reader,
                    direct.local_identity,
                )?));
            }
            if file.fd.is_pipe()
                && !file.fd.nonblocking()
                && matches!(file.operation, ByteOperation::Plain)
            {
                let mut bytes = Vec::new();
                let count = if byte_number(number) == 64 {
                    let count = args[2].min(crate::MAX_WRITE as u64) as usize;
                    if count > 4096 {
                        bytes.resize(count, 0);
                        reader.read(args[1], &mut bytes).map_err(|_| Errno(14))?;
                    }
                    count
                } else {
                    let mut args = args;
                    args[3] = 0;
                    let (parts, count) = Linux::positioned_vector_parts(&reader, args, true)?;
                    if count > 4096 {
                        Linux::gather_parts(&reader, &parts, count, &mut bytes)?;
                    }
                    count
                };
                if count > 4096 {
                    file.operation =
                        ByteOperation::Pipe(Arc::new(std::sync::Mutex::new(PipeWrite {
                            bytes,
                            written: 0,
                        })));
                }
            }
            Ok(())
        })();
        let mut result = match prepared {
            Ok(()) => {
                if let ByteOperation::Stream(write) = &file.operation {
                    Some(write.progress(&file.fd, &reader, &mut direct.scratch.borrow_mut()))
                } else if let ByteOperation::Pipe(write) = &file.operation {
                    Some(direct.transfer_pipe_write(&file.fd, write))
                } else if let ByteOperation::Tcp(tcp) = &file.operation {
                    Some(direct.transfer_tcp(tcp, byte_number(number), args, &mut reader))
                } else {
                    direct.transfer_fd(&file.fd, byte_number(number), args, &mut reader)
                }
            }
            Err(error) => Some(Err(error)),
        };
        self.fault = reader.fault();
        if self.fault.is_none() && number == 287 && args[5] & 6 != 0 {
            if let Some(Ok(_)) = result {
                result = Some(result.unwrap().and_then(|count| {
                    direct.paths.as_ref().ok_or(Errno(95))?.retained_control(
                        file.fd.shared_file().ok_or(Errno(9))?,
                        |vfs, alias| vfs.sync_fd(alias, args[5] & 4 == 0),
                    )?;
                    Ok(count)
                }));
            }
        }
        result
    }
}
pub(super) struct PathInput {
    pub(super) paths: trames_vfs::PathQueries,
    pub(super) files: trames_vfs::DirectFiles,
    pub(super) bytes: Bytes,
    mount_idmap: std::sync::OnceLock<Result<Arc<trames_vfs::MountIdmap>, Errno>>,
}
pub(super) enum Step {
    Pending(PageFault),
    Reply(trames_vfs::FileReply, file::FileOutput),
    Work(trames_vfs::FileWork, file::FileOutput),
    Fifo(trames_vfs::FifoOpen),
}
impl PathInput {
    pub(super) fn new(paths: trames_vfs::PathQueries, files: trames_vfs::DirectFiles) -> Self {
        Self {
            paths,
            files,
            bytes: Bytes::default(),
            mount_idmap: Default::default(),
        }
    }
    pub(super) fn read(&self, number: u32, a: [u64; 6], memory: &impl CpuMemory) -> Step {
        let mut reader = Reader::new(memory, &self.bytes);
        let result = self.import_and_run(number, a, &mut reader);
        if let Some(fault) = reader.fault() {
            return Step::Pending(fault);
        }
        match result {
            Ok(step) => step,
            Err(error) => Step::Reply(
                trames_vfs::FileReply {
                    resources: Default::default(),
                    result: Err(error),
                    file_size_signal: false,
                    scratch: None,
                },
                file::FileOutput::None,
            ),
        }
    }
    fn import_and_run(
        &self,
        number: u32,
        a: [u64; 6],
        reader: &mut impl CpuMemory,
    ) -> Result<Step, Errno> {
        if namespace::supported(number) {
            let (call, output) = namespace::import(
                number,
                a,
                reader,
                || self.paths.check_mount_admin(),
                |fd| {
                    self.mount_idmap
                        .get_or_init(|| self.paths.capture_mount_idmap(fd))
                        .clone()
                },
            )?;
            return Ok(match self.paths.namespace_attempt(call) {
                trames_vfs::NamespaceAttempt::Complete(reply) => Step::Reply(reply, output),
                trames_vfs::NamespaceAttempt::Retained(work) => Step::Work(work, output),
            });
        }
        if let Some(output) = crate::path_queries::file_output(number, a) {
            return Ok(
                match crate::path_queries::prepare_output(&self.paths, number, a, reader) {
                    Some(reply) => Step::Reply(reply, output),
                    None => Step::Work(self.paths.take_fuse_stat().ok_or(Errno(5))?, output),
                },
            );
        }
        if matches!(number, 56 | 437) {
            let (flags, mode, policy) = if number == 437 {
                Linux::decode_open_how(reader, a[2], a[3])?
            } else {
                (a[2] as u32, a[3] as u32, 0)
            };
            let path = Linux::path(reader, a[1])?;
            return Ok(
                match self.paths.open_at_resolve(
                    a[0] as i32,
                    &path,
                    flags,
                    mode,
                    policy,
                    &self.files,
                ) {
                    Some(result) => {
                        let fd = result?;
                        if let Some(open) = self.paths.pending_fifo_open(fd) {
                            Step::Fifo(open)
                        } else {
                            Step::Reply(
                                trames_vfs::FileReply {
                                    resources: Default::default(),
                                    result: Ok(trames_vfs::FileValue::Count(u64::from(fd))),
                                    file_size_signal: false,
                                    scratch: None,
                                },
                                file::FileOutput::None,
                            )
                        }
                    }
                    None => Step::Work(
                        self.paths.take_open_work().ok_or(Errno(5))?,
                        file::FileOutput::None,
                    ),
                },
            );
        }
        if number == 45 {
            if a[1] > i64::MAX as u64 {
                return Err(Errno(22));
            }
            let path = Linux::path(reader, a[0])?;
            return Ok(Step::Work(
                self.paths
                    .truncate_path_work(&path, a[1])
                    .ok_or(Errno(5))??,
                file::FileOutput::None,
            ));
        }
        // These path calls have no guest output and all pointer imports precede
        // their namespace effects. Read-only Reader cannot conceal an output.
        let result = crate::path_queries::call(&self.paths, number, a, reader);
        match result {
            Some(result) => Ok(Step::Reply(
                trames_vfs::FileReply {
                    resources: Default::default(),
                    result: result.map(trames_vfs::FileValue::Count),
                    file_size_signal: false,
                    scratch: None,
                },
                file::FileOutput::None,
            )),
            None => Ok(Step::Work(
                self.paths.take_fuse_stat().ok_or(Errno(5))?,
                file::FileOutput::None,
            )),
        }
    }
}
impl Input {
    pub(super) fn new(
        paths: trames_vfs::PathQueries,
        file: trames_vfs::FileTarget,
        regular: bool,
        unsigned: bool,
    ) -> Self {
        Self {
            paths,
            file,
            regular,
            unsigned,
            bytes: Bytes::default(),
        }
    }
    pub(super) fn read(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
        scratch: &mut Vec<u8>,
    ) -> (
        Result<(trames_vfs::FileCommand, file::FileOutput), Errno>,
        Option<PageFault>,
    ) {
        let reader = Reader::new(memory, &self.bytes);
        let result = file::import(number, args, &reader, scratch, self.regular, self.unsigned);
        (result, reader.fault())
    }
}
