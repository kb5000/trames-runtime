// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted filesystem operations. Host work owns original OFDs and owned bytes;
//! guest pointers, source task execution and descriptor membership stay outside.
use super::*;
use std::sync::atomic::AtomicUsize;
mod open;
mod read;
pub(super) use open::Request as ResourceOpen;
mod memory_control;
mod resize;
mod write;
pub(super) use write::Policy as WritePolicy;

#[derive(Clone)]
pub struct FileTarget(pub(super) SharedFd);
enum ProcReadOutcome {
    Complete(Result<FileValue>),
    Waiting(Vec<proc_file::ProcWait>),
}
impl ProcReadOutcome {
    fn new(result: proc_file::ProcRead, position: Option<crate::read_reply::FileRead>) -> Self {
        match result {
            proc_file::ProcRead::Complete(result) => {
                Self::Complete(result.map(|bytes| match position {
                    Some(position) => FileValue::Read(ReadReply::new(bytes, position)),
                    None => FileValue::Bytes(bytes),
                }))
            }
            proc_file::ProcRead::Waiting(pages) => Self::Waiting(pages),
        }
    }
}
impl FileTarget {
    /// Prepare one original FUSE file page for an embedding's PageBacking.
    /// This retains its OFD and cache charge, but does not admit mmap or shared
    /// writeback. First load needs the existing worker's FileActorScope.
    pub fn page_source(&self, offset: u64) -> Result<Option<Arc<dyn trames_memory::PageSource>>> {
        let Some(events::SharedControl::FuseFile(file)) = &self.0.open.control else {
            return Ok(None);
        };
        file.page_source(self.0.clone(), offset).map(Some)
    }

    pub(crate) fn daemon_backed(&self) -> bool {
        matches!(
            self.0.open.control,
            Some(events::SharedControl::FuseFile(_) | events::SharedControl::Fuse(_))
        ) || self.0.open.node.as_ref().is_some_and(|node| {
            node.fuse_directory.get().is_some() || node.fuse_leaf.get().is_some()
        })
    }
    fn proc_memory_command(&self, command: &FileCommand) -> bool {
        self.0
            .open
            .runtime_file
            .as_ref()
            .is_some_and(|f| f.is_memory() && f.memory_target().is_some())
            && matches!(
                command,
                FileCommand::Write { .. }
                    | FileCommand::WriteSync { .. }
                    | FileCommand::Read { .. }
            )
    }
    fn positioned_read(&self) -> bool {
        let open = &self.0.open;
        open.is_regular_file()
            || open.proc_control()
            || matches!(
                open.control,
                Some(events::SharedControl::Cgroup(_) | events::SharedControl::MessageQueue(_))
            )
    }
    fn position_command(&self, command: &FileCommand) -> bool {
        matches!(
            command,
            FileCommand::Read { offset: None, .. }
                | FileCommand::Write { offset: None, .. }
                | FileCommand::WriteSync { offset: None, .. }
                | FileCommand::Seek { .. }
        ) && self.positioned_read()
    }
    fn position_busy(&self, command: &FileCommand) -> bool {
        self.position_command(command) && self.0.open.file_position.lock().unwrap().pending != 0
    }

    pub fn read_zero_device(&self, copy: impl FnOnce() -> Result<u64>) -> Option<Result<u64>> {
        self.0.open.read_zero_device(copy)
    }

    pub fn unsigned_offsets(&self) -> bool {
        self.0
            .open
            .runtime_file
            .as_ref()
            .is_some_and(|f| f.is_memory())
    }
    pub fn regular_file(&self) -> bool {
        self.0.open.is_regular_file() && !self.unsigned_offsets()
    }

    fn proc_read(&self, command: &FileCommand) -> Option<ProcReadOutcome> {
        let FileCommand::Read { count, offset } = command else {
            return None;
        };
        let open = &self.0.open;
        let file = open.runtime_file.as_ref()?;
        if !file.live_payload() {
            return None;
        }
        if !fd_can_read(open.flags.get()) {
            return Some(ProcReadOutcome::Complete(Err(Errno(9))));
        }
        if let Some(offset) = offset {
            return Some(ProcReadOutcome::new(
                if *offset > i64::MAX as u64 && !file.is_memory() {
                    proc_file::ProcRead::Complete(Err(Errno(22)))
                } else {
                    file.read_payload(*offset, *count)
                },
                None,
            ));
        }
        let position = match crate::read_reply::FileRead::begin(self.0.clone()) {
            Ok(position) => position,
            Err(Errno(11)) => return Some(ProcReadOutcome::Waiting(Vec::new())),
            Err(error) => return Some(ProcReadOutcome::Complete(Err(error))),
        };
        Some(ProcReadOutcome::new(
            file.read_payload(position.offset, *count),
            Some(position),
        ))
    }
    fn waits(&self, command: &FileCommand) -> bool {
        if self.position_command(command) {
            return true;
        }
        if self.0.open.console.get().is_some()
            && self.0.open.flags.get() & O_NONBLOCK == 0
            && matches!(
                command,
                FileCommand::Read { offset: None, .. } | FileCommand::Write { offset: None, .. }
            )
        {
            return true;
        }
        matches!(command, FileCommand::Transfer(t) if t.lock().unwrap().waits())
            || matches!(command, FileCommand::Copy { transfer, .. } if transfer.lock().unwrap().io.blocked())
            || matches!(command, FileCommand::Read { .. })
                && self
                    .0
                    .open
                    .runtime_file
                    .as_ref()
                    .is_some_and(|file| file.live_payload())
    }
    /// Finish through the caller's existing mm before FileOutput can overwrite
    /// its source. None leaves both guest output and the original f_pos intact.
    pub fn proc_io_local(
        &self,
        command: &FileCommand,
        memory: &mut impl trames_memory::CpuMemory,
    ) -> Option<Result<FileValue>> {
        let open = &self.0.open;
        let file = open.runtime_file.as_ref()?;
        if let FileCommand::Write { bytes, offset } | FileCommand::WriteSync { bytes, offset, .. } =
            command
        {
            if !file.is_memory() {
                return None;
            }
            if !fd_can_write(open.flags.get()) {
                return Some(Err(Errno(9)));
            }
            if file.memory_target().is_some() || !file.local_memory(memory) {
                return None;
            }
            if let Some(offset) = offset {
                return Some(if *offset > i64::MAX as u64 && !file.is_memory() {
                    Err(Errno(22))
                } else {
                    file.write_local(*offset, bytes, memory)
                        .map(FileValue::Count)
                });
            }
            let mut position = open.file_position.lock().unwrap();
            if position.pending != 0 {
                return None;
            }
            return Some(file.write_local(position.value, bytes, memory).map(|n| {
                position.value += n;
                FileValue::Count(n)
            }));
        }
        self.proc_read_local(command, memory)
    }
    pub fn proc_read_local(
        &self,
        command: &FileCommand,
        memory: &impl trames_memory::CpuMemory,
    ) -> Option<Result<FileValue>> {
        let FileCommand::Read { count, offset } = command else {
            return None;
        };
        let open = &self.0.open;
        let file = open.runtime_file.as_ref()?;
        if file.is_memory() && file.memory_target().is_some() {
            return None;
        }
        if !file.live_payload() {
            return None;
        }
        if !fd_can_read(open.flags.get()) {
            return Some(Err(Errno(9)));
        }
        if let Some(offset) = offset {
            if *offset > i64::MAX as u64 && !file.is_memory() {
                return Some(Err(Errno(22)));
            }
            return file
                .read_local(*offset, *count, memory)
                .map(|r| r.map(FileValue::Bytes));
        }
        let position = crate::read_reply::FileRead::begin(self.0.clone()).ok()?;
        file.read_local(position.offset, *count, memory)
            .map(|result| result.map(|bytes| FileValue::Read(ReadReply::new(bytes, position))))
    }
    pub fn status_flags(&self) -> u32 {
        self.0.open.flags.get()
    }
    pub fn identity(&self) -> usize {
        self.0.identity()
    }
    pub fn shared_file(&self) -> SharedFd {
        self.0.clone()
    }
    /// Original inode admission is available without waiting for native I/O's
    /// node borrow, and is shared by every open description of that inode.
    pub fn layout(&self) -> Option<Arc<trames_memory::layout::Layout>> {
        self.0
            .open
            .node
            .as_ref()
            .map(|node| node.layout.get_or_init(Default::default).clone())
    }
    pub fn host_work_owned(&self, command: &FileCommand) -> bool {
        if let Some(console) = self.0.open.console.get() {
            return matches!(
                command,
                FileCommand::Read { offset: None, .. } | FileCommand::Write { offset: None, .. }
            ) && console.io.host_work();
        }
        if self
            .0
            .open
            .node
            .as_ref()
            .is_some_and(|n| n.active_file_work.load(Ordering::Relaxed) != 0)
        {
            return true;
        }
        match command {
            FileCommand::Transfer(transfer) => transfer.lock().unwrap().host_work_owned(),
            FileCommand::Read { count, .. } if *count < 16 * 1024 => false,
            FileCommand::Write { bytes, .. }
                if bytes.len() < 16 * 1024 && self.0.open.flags.get() & 0x1000 == 0 =>
            {
                false
            }
            _ => self.host_work(command),
        }
    }
    fn layout_domains(&self) -> Vec<u64> {
        let Some(node) = &self.0.open.node else {
            return Vec::new();
        };
        let node = node.borrow();
        match &node.content {
            Content::File(storage::FileData::Mapped(data)) => data.layout_domains().to_vec(),
            _ => Vec::new(),
        }
    }
    pub fn host_work(&self, operation: &FileCommand) -> bool {
        if let Some(console) = self.0.open.console.get() {
            return matches!(
                operation,
                FileCommand::Read { offset: None, .. } | FileCommand::Write { offset: None, .. }
            ) && console.io.host_work();
        }
        if let FileCommand::Transfer(transfer) = operation {
            return transfer.lock().unwrap().host_work();
        }
        if matches!(
            operation,
            FileCommand::Sync { .. }
                | FileCommand::SyncFilesystem
                | FileCommand::SyncAll
                | FileCommand::Copy { .. }
        ) {
            return true;
        }
        let open = &self.0.open;
        if let FileCommand::SyncRange { flags, .. } = operation {
            if *flags == 0 || open.flags.get() & O_PATH != 0 {
                return false;
            }
            #[cfg(all(feature = "hostfs", unix))]
            if open.host_file.is_some() {
                return true;
            }
        }
        let Some(node) = &open.node else {
            return false;
        };
        let Some(node) = node.try_borrow() else {
            return true;
        };
        let Content::File(data) = &node.content else {
            return false;
        };
        let persistent = data.disk_source().is_some();
        match operation {
            FileCommand::Copy { .. } => true,
            FileCommand::Transfer(transfer) => transfer.lock().unwrap().host_work(),
            FileCommand::Seek { .. } => persistent,
            FileCommand::Stat | FileCommand::ReadDirectory { .. } => false,
            FileCommand::Seals(add) => add.is_some_and(|add| add & 8 != 0) && data.mapped_work(),
            FileCommand::Read { .. } => persistent,
            FileCommand::Write { .. } | FileCommand::WriteSync { .. } => persistent,
            FileCommand::Sync { .. }
            | FileCommand::SyncRange { .. }
            | FileCommand::SyncFilesystem
            | FileCommand::SyncAll => persistent || data.mapped_work(),
            FileCommand::Truncate(_) | FileCommand::TruncateOpen | FileCommand::Allocate { .. } => {
                persistent || data.mapped_work()
            }
        }
    }
}
impl SharedFd {
    pub fn filesystem_target(&self) -> FileTarget {
        FileTarget(self.clone())
    }
    /// Descriptor kinds whose byte call terminates in the canonical VFS body.
    /// This grants no signal reader, socket transport or device data provider.
    pub fn nonbyte_target(&self) -> Option<FileTarget> {
        (self.open.namespace_resource.is_some()
            || matches!(
                &self.open.control,
                Some(
                    events::SharedControl::Uring(_)
                        | events::SharedControl::Bpf(_)
                        | events::SharedControl::Epoll(_)
                )
            )
            || self.open.node.as_ref().is_some_and(|node| {
                !node.regular_file
                    && matches!(
                        node.borrow().content,
                        Content::Directory | Content::Symlink(_)
                    )
            }))
        .then(|| self.filesystem_target())
    }
    pub fn file_target(&self) -> Option<FileTarget> {
        let open = &self.open;
        if open
            .console
            .get()
            .is_some_and(|console| console.io.host_work())
        {
            return Some(FileTarget(self.clone()));
        }
        if matches!(
            open.control,
            Some(
                events::SharedControl::FuseFile(_)
                    | events::SharedControl::Fuse(_)
                    | events::SharedControl::Cgroup(_)
                    | events::SharedControl::MessageQueue(_)
            )
        ) {
            return Some(FileTarget(self.clone()));
        }
        if open.control.is_some()
            || !open.proc_control() && !open.node.as_ref().is_some_and(|node| node.regular_file)
        {
            return None;
        }
        Some(FileTarget(self.clone()))
    }
}

#[derive(Clone)]
pub enum FileCommand {
    ReadDirectory {
        count: usize,
    },
    Seals(Option<u32>),
    Read {
        count: usize,
        offset: Option<u64>,
    },
    Write {
        bytes: Vec<u8>,
        offset: Option<u64>,
    },
    WriteSync {
        bytes: Vec<u8>,
        offset: Option<u64>,
        data_only: bool,
    },
    Truncate(u64),
    /// Path resolution already checked O_TRUNC write permission. The resulting
    /// description can still be O_RDONLY; ftruncate retains its separate rule.
    TruncateOpen,
    Allocate {
        mode: u64,
        offset: u64,
        length: u64,
    },
    Sync {
        data_only: bool,
    },
    SyncRange {
        offset: u64,
        length: u64,
        flags: u32,
    },
    SyncFilesystem,
    SyncAll,
    Seek {
        offset: i64,
        whence: u32,
    },
    Stat,
    Transfer(Arc<std::sync::Mutex<StreamTransfer>>),
    Copy {
        input: FileTarget,
        transfer: Arc<std::sync::Mutex<FileCopy>>,
    },
}
pub enum FileValue {
    LocalConnection(LocalConnection),
    LocalDatagram(LocalDatagram),
    Read(ReadReply),
    Directory(fuse::DirectoryReply),
    FuseStat([u8; 128], StatMount),
    Stat([u8; 128]),
    Transfer {
        count: u64,
        from: u64,
        to: Option<u64>,
    },
    Count(u64),
    Bytes(Vec<u8>),
}
pub struct FileReply {
    pub result: Result<FileValue>,
    pub resources: FileResources,
    pub file_size_signal: bool,
    pub scratch: Option<Vec<u8>>,
}
pub enum FileOutcome {
    Complete(FileReply),
    /// The source task parks with its original resources and committed progress.
    Waiting(FileWork),
    /// A mapping-layout boundary. A copy retains its committed prefix, current
    /// offsets and accepted input for the chunk awaiting the layout change.
    Layout(FileWork),
    /// A namespace call or accepted pathname continuation reached an original
    /// owner-only resource before effects. Its original operands/resources survive.
    Owner(FileWork),
}
pub struct FileWork {
    memory: trames_memory::CgroupMemoryContext,
    io: cgroup::IoContext,
    paths: Box<PathQueries>,
    target: Option<FileTarget>,
    _transfer: Option<TransferLease>,
    command: FileCommand,
    exclusive: bool,
    layout_exclusive: Option<trames_memory::layout::LayoutExclusive>,
    fuse_layout: Option<Arc<trames_memory::layout::Layout>>,
    active: Option<FileActive>,
    input_active: Option<FileActive>,
    open: Option<Box<PreparedOpen>>,
    resource_open: Option<Box<ResourceOpen>>,
    path_retry: Option<Box<PathRevalidation>>,
    sync_targets: Option<Vec<storage::FilesystemSync>>,
    namespace: Option<Box<namespace_work::NamespaceWork>>,
    proc_wait: Vec<proc_file::ProcWait>,
    proc_memory: Option<Box<ProcMemory>>,
    fuse_stat: Option<Box<fuse::Metadata>>,
    linger: Option<Box<trames_net::TcpLinger>>,
    resource_wait: Option<Arc<trames_memory::PageWait>>,
    read: Option<Box<read::Cursor>>,
    write: Option<Box<write::Cursor>>,
    memory_control: Option<Box<memory_control::Cursor>>,
    sync: Option<Box<write::Sync>>,
    mutation: Option<Box<resize::Mutation>>,
    copy_tail: Option<write::CopyTail>,
    write_end: Option<Arc<std::sync::atomic::AtomicU64>>,
}
struct ProcMemory {
    request: Option<Arc<trames_memory::TransferRequest>>,
    position: Option<Arc<ProcPosition>>,
    address: u64,
    writing: bool,
    requested: usize,
    expected: usize,
    done: usize,
    output: Vec<u8>,
}
impl ProcMemory {
    fn value(&mut self) -> FileValue {
        if self.writing {
            FileValue::Count(self.done as u64)
        } else {
            let bytes = std::mem::take(&mut self.output);
            match self.position.take() {
                Some(position) => FileValue::Read(ReadReply::new(bytes, position)),
                None => FileValue::Bytes(bytes),
            }
        }
    }
}
struct ProcPosition {
    _file: SharedFd,
    position: Arc<file_data::FilePosition>,
    offset: u64,
    committed: AtomicUsize,
}
impl ProcPosition {
    fn record(&self, count: usize) {
        self.committed.store(count, Ordering::Relaxed);
    }
}
impl crate::read_reply::CommitRead for Arc<ProcPosition> {
    fn commit(&self, copied: usize) {
        self.record(copied);
    }
}
impl Drop for ProcPosition {
    fn drop(&mut self) {
        {
            let mut state = self.position.lock().unwrap();
            state.value = self.offset.wrapping_add(*self.committed.get_mut() as u64);
            state.pending -= 1;
        }
        self.position.notify_pending();
    }
}
struct FileActive(Arc<Inode>);
enum TransferLease {
    Copy(Arc<std::sync::Mutex<FileCopy>>),
    Stream(Arc<std::sync::Mutex<StreamTransfer>>),
}
impl TransferLease {
    fn new(command: &FileCommand) -> Option<Self> {
        match command {
            FileCommand::Copy { transfer, .. } => Some(Self::Copy(transfer.clone())),
            FileCommand::Transfer(transfer) => Some(Self::Stream(transfer.clone())),
            _ => None,
        }
    }
}
impl Drop for TransferLease {
    fn drop(&mut self) {
        let (request, retired): (_, Box<dyn Send>) = match self {
            Self::Copy(transfer) => {
                let mut transfer = transfer.lock().unwrap();
                (
                    transfer.io.fuse_signal_request(),
                    Box::new(transfer.cancel_pending()),
                )
            }
            Self::Stream(transfer) => {
                let mut transfer = transfer.lock().unwrap();
                (
                    transfer.io.fuse_signal_request(),
                    Box::new(transfer.cancel_pending()),
                )
            }
        };
        // Original resource callbacks run outside the per-call state mutex.
        // A daemon keeps this receipt until its cancellation becomes terminal.
        let retired = match request {
            Some(request) => request.retain_cancellation(retired),
            None => Some(retired),
        };
        drop(retired);
    }
}
impl Drop for FileActive {
    fn drop(&mut self) {
        self.0.active_file_work.fetch_sub(1, Ordering::Relaxed);
    }
}
pub(super) struct PreparedOpen {
    pub(super) _truncate_access: Option<executable::WriteAccess>,
    pub(super) reservation: fd_table::ReservedFd,
    pub(super) target: FileTarget,
    pub(super) cloexec: CloseOnExec,
    pub(super) publication: Option<DirectFiles>,
}
// Cold pathname -> native truncate fallback. The typed descriptor work keeps
// using its accepted OFD; only ESTALE may return to this original path context.
struct PathRevalidation {
    paths: Box<PathQueries>,
    pending: Box<fuse::Metadata>,
}
impl PreparedOpen {
    fn publish(self, paths: &PathQueries) -> Result<u32> {
        let descriptor = Descriptor {
            open: OpenHandle::Shared(self.target.0.open),
            cloexec: self.cloexec,
        };
        if let Some(publication) = &self.publication {
            publication.publish_open(&paths.view.borrow(), &descriptor.open.borrow());
        }
        self.reservation.publish(descriptor, None)
    }
}
impl FileWork {
    pub(super) fn resource_pending(&self) -> bool {
        // Classification is independent of transient readiness: another
        // waiter may acquire/release the resource between the caller's checks.
        self.resource_wait.is_some()
            || self
                .command
                .transfer_io(transfer_io::Io::resource_pending)
                .unwrap_or(false)
    }
    /// Cold non-data descriptors use their canonical ABI body rather than the
    /// regular-file write specialization. No byte provider or host job is added.
    pub fn descriptor_reply(
        paths: &PathQueries,
        target: FileTarget,
        mut command: FileCommand,
    ) -> FileReply {
        let scope = crate::output_resources::OutputScope::enter();
        command.retain_output_inputs();
        let original = target.0.clone();
        let result = paths.retained_control(target.0, |vfs, fd| command.execute(vfs, fd));
        Self::descriptor_result(result, &mut command)
            .retain_file(Some(original))
            .retain_output(scope.finish())
    }
    pub fn descriptor_owned(
        vfs: &mut Vfs,
        target: FileTarget,
        mut command: FileCommand,
    ) -> FileReply {
        let scope = crate::output_resources::OutputScope::enter();
        command.retain_output_inputs();
        let result = vfs.with_uring_fd(&target.0.clone().retained(), |vfs, fd| {
            command.execute(vfs, fd)
        });
        Self::descriptor_result(result, &mut command)
            .retain_file(Some(target.0))
            .retain_output(scope.finish())
    }
    fn descriptor_result(result: Result<FileValue>, command: &mut FileCommand) -> FileReply {
        let scratch = match command {
            FileCommand::Write { bytes, .. } | FileCommand::WriteSync { bytes, .. } => {
                Some(std::mem::take(bytes))
            }
            _ => None,
        };
        FileReply {
            resources: Default::default(),
            result,
            file_size_signal: false,
            scratch,
        }
    }

    fn fuse_request(&self) -> Option<&fuse::Metadata> {
        self.fuse_stat
            .as_deref()
            .or_else(|| self.namespace.as_ref().and_then(|ns| ns.fuse_request()))
    }
    pub fn waits_for_fuse(&self) -> bool {
        self.fuse_signal_request().is_some()
    }
    pub fn interruptible_wait(&self) -> bool {
        if self
            .namespace
            .as_ref()
            .is_some_and(|work| !work.interruptible_wait())
        {
            return false;
        }
        if self
            .resource_wait
            .as_ref()
            .is_some_and(|wait| !wait.ready())
            && self.fuse_request().is_none()
        {
            return self.sync.is_none()
                && self.mutation.is_none()
                && !self
                    .command
                    .transfer_io(transfer_io::Io::retained)
                    .unwrap_or(false)
                && self
                    .write
                    .as_ref()
                    .is_none_or(|write| write.interruptible());
        }
        // These are original inode/OFD mutex transactions. Caught handlers
        // cannot cross their retained operation and replay its source inputs.
        self.fuse_request().is_none()
            && !self
                .command
                .transfer_io(transfer_io::Io::retained)
                .unwrap_or(false)
            && !self
                .command
                .transfer_io(transfer_io::Io::blocked)
                .unwrap_or(false)
            && !self
                .target
                .as_ref()
                .is_some_and(|target| target.position_busy(&self.command))
            && !self
                .position_wait()
                .is_some_and(|file| file.waiting_for(&self.command))
    }
    /// Finish a caught signal from a parked original operation. Its original
    /// byte prefix belongs to this call and must never be guest-replayed.
    pub fn interrupted(mut self) -> FileReply {
        if let Some(cursor) = self.memory_control.take() {
            return Self::descriptor_result(Ok(cursor.finish()), &mut self.command)
                .retain_file(self.target.as_ref().map(|target| target.0.clone()));
        }
        if self.read.is_some() {
            let result = self.finish_read(Err(Errno(4)));
            return Self::descriptor_result(result, &mut self.command)
                .retain_file(self.target.as_ref().map(|target| target.0.clone()));
        }
        let progress = self.write.as_ref().map_or(0, |write| write.progress());
        let signal = self
            .write
            .as_ref()
            .is_some_and(|write| write.file_size_signal());
        let result = if progress == 0 {
            Err(Errno(4))
        } else {
            Ok(FileValue::Count(progress as u64))
        };
        let mut reply = Self::descriptor_result(result, &mut self.command);
        reply.file_size_signal = signal;
        reply.retain_file(self.target.as_ref().map(|target| target.0.clone()))
    }
    pub fn fuse_interrupt_needed(&self) -> bool {
        self.fuse_request().is_some_and(|p| p.needs_interrupt())
            || self
                .command
                .transfer_io(transfer_io::Io::fuse_interrupt_needed)
                .unwrap_or(false)
    }
    pub fn fuse_signal_request(&self) -> Option<Arc<fuse::Request>> {
        self.fuse_request()
            .and_then(|p| p.daemon_request())
            .cloned()
            .or_else(|| {
                self.command
                    .transfer_io(transfer_io::Io::fuse_signal_request)
                    .flatten()
            })
    }
    fn position_wait(&self) -> Option<&fuse::File> {
        if matches!(
            self.command,
            FileCommand::Copy { .. } | FileCommand::Transfer(_)
        ) {
            return None;
        }
        let target = self.target.as_ref()?;
        if let Some(events::SharedControl::FuseFile(file)) = &target.0.open.control {
            Some(file)
        } else {
            None
        }
    }
    pub fn waiting(&self) -> bool {
        if self
            .resource_wait
            .as_ref()
            .is_some_and(|wait| !wait.ready())
        {
            return true;
        }
        if self
            .command
            .transfer_io(transfer_io::Io::blocked)
            .unwrap_or(false)
        {
            return true;
        }
        if self.proc_memory.is_some()
            || self.read.is_none()
                && self.write.is_none()
                && self.memory_control.is_none()
                && self
                    .target
                    .as_ref()
                    .is_some_and(|t| t.position_busy(&self.command))
        {
            return true;
        }

        if let Some(wait) = &self.linger {
            return !wait.ready();
        }
        if let Some(p) = &self.fuse_stat {
            return !p.ready();
        }
        if let Some(file) = self.position_wait() {
            return file.waiting_for(&self.command);
        }
        if self.console_wait().is_some() {
            return !self.ready();
        }
        if let Some(device) = self.device_read_wait() {
            return device.poll(1).0 == 0;
        }
        self.namespace.as_ref().is_some_and(|work| work.waiting())
            || !self.proc_wait.is_empty()
            || matches!(&self.command, FileCommand::Transfer(t) if t.lock().unwrap().waits())
    }
    pub fn ready(&self) -> bool {
        if self
            .resource_wait
            .as_ref()
            .is_some_and(|wait| !wait.ready())
        {
            return false;
        }
        if !self
            .command
            .transfer_io(transfer_io::Io::ready)
            .unwrap_or(true)
        {
            return false;
        }
        if let Some(io) = &self.proc_memory {
            return io.request.as_ref().is_none_or(|r| r.ready());
        }
        if self.read.is_none()
            && self.write.is_none()
            && self.memory_control.is_none()
            && self
                .target
                .as_ref()
                .is_some_and(|t| t.position_busy(&self.command))
        {
            return false;
        }

        if let Some(wait) = &self.linger {
            return wait.ready();
        }
        if let Some(p) = &self.fuse_stat {
            return p.ready();
        }
        if let Some(file) = self.position_wait() {
            return !file.waiting_for(&self.command);
        }
        if let Some((console, writing)) = self.console_wait() {
            return console
                .io
                .poll(console.stream, if writing { 4 } else { 1 })
                .0
                != 0;
        }
        if let Some(device) = self.device_read_wait() {
            return device.poll(1).0 != 0;
        }
        if let Some(work) = &self.namespace {
            return work.ready();
        }
        match &self.command {
            FileCommand::Transfer(t) => t.lock().unwrap().ready(),
            _ => self.proc_wait.iter().all(|page| page.ready()),
        }
    }
    pub fn wait_sources(&self, signal: &Arc<IoSignal>) -> std::io::Result<TransferWait> {
        // Observe changes before checking readiness; another contender can
        // acquire/release this original transaction during those checks.
        let resource_changes = self
            .resource_wait
            .as_ref()
            .map(|wait| wait.subscribe_changes(signal));
        let mut wait = self.resource_wait_sources(signal)?;
        if let Some(changes) = resource_changes {
            wait.subscriptions.extend(changes);
        }
        // A position can become busy after subscription but before ready().
        // Subscribe even when currently idle, alongside the actual page/proc
        // dependency; choosing only one loses either kind of completion.
        if let Some(target) = self.target.as_ref().filter(|target| {
            self.read.is_none()
                && self.write.is_none()
                && self.memory_control.is_none()
                && target.position_command(&self.command)
                && !matches!(
                    target.0.open.control,
                    Some(events::SharedControl::FuseFile(_))
                )
        }) {
            wait.subscriptions
                .push(target.0.open.file_position.subscribe_pending(signal));
        }
        Ok(wait)
    }
    fn resource_wait_sources(&self, signal: &Arc<IoSignal>) -> std::io::Result<TransferWait> {
        if let Some(wait) = self.resource_wait.as_ref().filter(|wait| !wait.ready()) {
            return Ok(TransferWait {
                subscriptions: wait.subscribe(signal),
                native: Vec::new(),
                deadline: wait.deadline(),
            });
        }
        if self
            .command
            .transfer_io(transfer_io::Io::blocked)
            .unwrap_or(false)
        {
            return self
                .command
                .transfer_io(|io| io.wait_sources(signal))
                .unwrap();
        }
        if let Some(request) = self.proc_memory.as_ref().and_then(|io| io.request.as_ref()) {
            return Ok(TransferWait {
                subscriptions: vec![request.subscribe(signal)],
                native: Vec::new(),
                deadline: None,
            });
        }
        if let Some(wait) = &self.linger {
            return Ok(TransferWait {
                subscriptions: wait.subscribe(signal).into_iter().collect(),
                native: vec![],
                deadline: Some(wait.deadline()),
            });
        }
        if let Some(p) = &self.fuse_stat {
            return Ok(TransferWait {
                subscriptions: p.subscribe(signal).into_iter().collect(),
                native: vec![],
                deadline: None,
            });
        }
        if let Some(file) = self.position_wait() {
            return Ok(TransferWait {
                subscriptions: file.subscribe_operation(&self.command, signal),
                native: vec![],
                deadline: None,
            });
        }
        if let Some((console, writing)) = self.console_wait() {
            let subscriptions = console.io.subscribe(signal);
            let native: Vec<_> = console
                .io
                .native_wait_fds(console.stream)
                .into_iter()
                .map(|fd| (fd, writing))
                .collect();
            if subscriptions.is_empty() && native.is_empty() {
                return Err(std::io::Error::last_os_error());
            }
            return Ok(TransferWait {
                subscriptions,
                native,
                deadline: None,
            });
        }
        if let Some(device) = self.device_read_wait() {
            return Ok(TransferWait {
                subscriptions: vec![device.subscribe(signal)],
                native: Vec::new(),
                deadline: None,
            });
        }
        if let Some(work) = &self.namespace {
            return Ok(work.wait_sources(signal));
        }
        match &self.command {
            FileCommand::Transfer(t) => t.lock().unwrap().wait_sources(signal),
            _ => Ok(TransferWait {
                subscriptions: self.proc_wait.iter().map(|p| p.subscribe(signal)).collect(),
                native: Vec::new(),
                deadline: None,
            }),
        }
    }
    fn proc_outcome(result: ProcReadOutcome, work: impl FnOnce() -> Self) -> FileOutcome {
        match result {
            ProcReadOutcome::Complete(result) => FileOutcome::Complete(FileReply {
                resources: Default::default(),
                result,
                file_size_signal: false,
                scratch: None,
            }),
            ProcReadOutcome::Waiting(pages) => {
                let mut work = work();
                work.proc_wait = pages;
                FileOutcome::Waiting(work)
            }
        }
    }
    pub fn transfer_native_fds(&self) -> Vec<HostFd> {
        if let Some((console, _)) = self.console_wait() {
            return console.io.native_wait_fds(console.stream);
        }
        match &self.command {
            FileCommand::Transfer(t) => t.lock().unwrap().native_wait_fds(),
            _ => Vec::new(),
        }
    }

    fn console_wait(&self) -> Option<(&console::ConsoleEndpoint, bool)> {
        let target = self.target.as_ref()?;
        if target.0.open.flags.get() & O_NONBLOCK != 0 {
            return None;
        }
        let console = target.0.open.console.get()?;
        let writing = match self.command {
            FileCommand::Read { offset: None, .. } => false,
            FileCommand::Write { offset: None, .. } => true,
            _ => return None,
        };
        Some((console, writing))
    }
    fn device_read_wait(&self) -> Option<&fuse::Device> {
        let target = self.target.as_ref()?;
        if target.0.open.flags.get() & O_NONBLOCK != 0
            || !matches!(self.command, FileCommand::Read { offset: None, .. })
        {
            return None;
        }
        match &target.0.open.control {
            Some(events::SharedControl::Fuse(device)) => Some(device),
            _ => None,
        }
    }

    /// Owned staging only, not file size or a guest mapping quota.
    pub fn buffered_bytes(&self) -> usize {
        match &self.command {
            FileCommand::Read { count, .. } => *count,
            FileCommand::Write { bytes, .. } | FileCommand::WriteSync { bytes, .. } => bytes.len(),
            _ => 0,
        }
    }
    pub(super) fn namespace(paths: PathQueries, namespace: namespace_work::NamespaceWork) -> Self {
        Self {
            memory: trames_memory::CgroupMemoryContext::capture(),
            namespace: Some(Box::new(namespace)),
            ..Self::sync_all(paths)
        }
    }
    /// A pathname continuation rejoins its original published metadata at the
    /// existing owner checkpoint, then returns to ordinary scheduling. It may
    /// encounter another daemon or native stage and must keep the same work.
    pub fn resume_owner(mut self, vfs: &mut Vfs) -> FileOutcome {
        if self
            .command
            .transfer_io(transfer_io::Io::owner)
            .unwrap_or(false)
        {
            self.command.transfer_io_mut(|io| io.resume_owner(vfs));
            return FileOutcome::Waiting(self);
        }
        if self
            .fuse_stat
            .as_ref()
            .is_some_and(|pending| pending.owner_work())
            || self
                .namespace
                .as_ref()
                .is_some_and(|pending| pending.owner_work())
        {
            self.paths
                .view
                .borrow_mut()
                .query
                .as_mut()
                .unwrap()
                .joined_owner = true;
            if let Some(pending) = &mut self.fuse_stat {
                pending.join_owner();
            }
            if let Some(pending) = &mut self.namespace {
                pending.join_owner();
            }
            FileOutcome::Waiting(self)
        } else {
            FileOutcome::Complete(self.run_owner(vfs))
        }
    }
    pub fn run_owner(self, vfs: &mut Vfs) -> FileReply {
        let _memory = self.memory.enter();
        let _io = self.io.enter();
        let scope = crate::output_resources::OutputScope::enter();
        let result = self
            .namespace
            .as_ref()
            .expect("retained namespace owner call")
            .run_owner(&self.paths, vfs);
        FileReply {
            resources: Default::default(),
            result,
            file_size_signal: false,
            scratch: None,
        }
        .retain_output(scope.finish())
    }
    pub fn sync_all(paths: PathQueries) -> Self {
        Self {
            memory: trames_memory::CgroupMemoryContext::capture(),
            io: cgroup::IoContext::capture(),
            paths: Box::new(paths),
            target: None,
            _transfer: None,
            command: FileCommand::SyncAll,
            exclusive: false,
            layout_exclusive: None,
            fuse_layout: None,
            active: None,
            input_active: None,
            open: None,
            resource_open: None,
            path_retry: None,
            sync_targets: None,
            namespace: None,
            proc_wait: Vec::new(),
            proc_memory: None,
            fuse_stat: None,
            linger: None,
            resource_wait: None,
            read: None,
            write: None,
            memory_control: None,
            sync: None,
            mutation: None,
            copy_tail: None,
            write_end: None,
        }
    }
    pub fn host_work(&self) -> bool {
        if self
            .resource_wait
            .as_ref()
            .is_some_and(|wait| !wait.ready())
        {
            return false;
        }
        if self
            .command
            .transfer_io(|io| io.blocked() && !io.ready())
            .unwrap_or(false)
        {
            return false;
        }
        if self.target.as_ref().is_some_and(|t| {
            t.proc_memory_command(&self.command)
                || self.read.is_none()
                    && self.write.is_none()
                    && self.memory_control.is_none()
                    && t.position_busy(&self.command)
        }) {
            return false;
        }

        if let Some(pending) = &self.fuse_stat {
            return pending.host_work();
        }
        if self.linger.is_some() {
            return false;
        }
        if let Some(namespace) = &self.namespace {
            return namespace.host_work();
        }
        self.command
            .transfer_io(transfer_io::Io::host_work)
            .unwrap_or(false)
            || self
                .target
                .as_ref()
                .is_none_or(|target| target.host_work(&self.command))
    }
    pub fn new(paths: &PathQueries, target: FileTarget, command: FileCommand) -> Self {
        Self {
            memory: trames_memory::CgroupMemoryContext::capture(),
            io: cgroup::IoContext::capture(),
            paths: Box::new(paths.file_context(&target, &command)),
            target: Some(target),
            _transfer: TransferLease::new(&command),
            command,
            exclusive: false,
            layout_exclusive: None,
            fuse_layout: None,
            active: None,
            input_active: None,
            open: None,
            resource_open: None,
            path_retry: None,
            sync_targets: None,
            namespace: None,
            proc_wait: Vec::new(),
            proc_memory: None,
            fuse_stat: None,
            linger: None,
            resource_wait: None,
            read: None,
            write: None,
            memory_control: None,
            sync: None,
            mutation: None,
            copy_tail: None,
            write_end: None,
        }
    }
    pub fn from_vfs(vfs: &Vfs, target: FileTarget, command: FileCommand) -> Self {
        Self {
            memory: trames_memory::CgroupMemoryContext::capture(),
            io: cgroup::IoContext::capture(),
            paths: Box::new(PathQueries::file_view(vfs, &target, &command)),
            target: Some(target),
            _transfer: TransferLease::new(&command),
            command,
            exclusive: false,
            layout_exclusive: None,
            fuse_layout: None,
            active: None,
            input_active: None,
            open: None,
            resource_open: None,
            path_retry: None,
            sync_targets: None,
            namespace: None,
            proc_wait: Vec::new(),
            proc_memory: None,
            fuse_stat: None,
            linger: None,
            resource_wait: None,
            read: None,
            write: None,
            memory_control: None,
            sync: None,
            mutation: None,
            copy_tail: None,
            write_end: None,
        }
    }
    pub fn queued(mut self) -> Self {
        if self.fuse_stat.is_none()
            && self.linger.is_none()
            && self.namespace.is_none()
            && self.sync_targets.is_none()
            && (matches!(self.command, FileCommand::SyncAll)
                || matches!(self.command, FileCommand::SyncFilesystem)
                    && self
                        .target
                        .as_ref()
                        .is_some_and(|t| t.status_flags() & O_PATH == 0))
        {
            let view = self.paths.view.borrow();
            let all = matches!(self.command, FileCommand::SyncAll);
            let selected = self
                .target
                .as_ref()
                .and_then(|target| target.0.open.mount_resource.get())
                .map_or(&view.fs, |mount| &mount.fs);
            let storage = if all {
                view.sync_targets(true)
            } else {
                vec![storage::FilesystemSync::new(selected.clone())]
            };
            self.sync_targets = Some(
                storage
                    .into_iter()
                    .map(storage::FilesystemSync::queued)
                    .collect(),
            );
            let mut filesystems = BTreeMap::new();
            if all {
                if let Some(fs) = &view.fs.fuse {
                    filesystems.insert(view.fs.identity(), fs.clone());
                }
                for mount in view
                    .mount_resources
                    .borrow()
                    .iter()
                    .filter_map(std::sync::Weak::upgrade)
                {
                    if let Some(fs) = &mount.fs.fuse {
                        filesystems
                            .entry(mount.fs.identity())
                            .or_insert_with(|| fs.clone());
                    }
                }
            } else if let Some(fs) = &selected.fuse {
                filesystems.insert(selected.identity(), fs.clone());
            }
            self.fuse_stat =
                fuse::Metadata::sync_filesystems(&view, filesystems.into_values().collect(), all)
                    .map(Box::new);
        }
        if self.input_active.is_none() {
            let input = match &self.command {
                FileCommand::Copy { input, .. } => Some(input.clone()),
                FileCommand::Transfer(t) => t.lock().unwrap().input.file_target(),
                _ => None,
            };
            if let Some(input) = input {
                if let Some(node) = input.0.open.node.as_ref() {
                    node.active_file_work.fetch_add(1, Ordering::Relaxed);
                    self.input_active = Some(FileActive(node.clone()));
                }
            }
        }
        if self.active.is_none() {
            if let Some(node) = self
                .target
                .as_ref()
                .and_then(|target| target.0.open.node.as_ref())
            {
                node.active_file_work.fetch_add(1, Ordering::Relaxed);
                self.active = Some(FileActive(node.clone()));
            }
        }
        self
    }
    /// Joined caller execution, with the same original VFS ownership contract.
    /// As for Vfs::truncate_fd, layout mutation requires joined execution Views.
    pub fn run_owned(vfs: &mut Vfs, target: FileTarget, command: FileCommand) -> FileOutcome {
        let memory = trames_memory::CgroupMemoryContext::capture();
        let _memory = memory.enter();
        let io = cgroup::IoContext::capture();
        let _io = io.enter();
        let scope = crate::output_resources::OutputScope::enter();
        let original = target.0.clone();
        Self::run_owned_inner(vfs, target, command)
            .retain_file(Some(original))
            .retain_output(scope.finish())
    }
    fn run_owned_inner(vfs: &mut Vfs, target: FileTarget, mut command: FileCommand) -> FileOutcome {
        command.retain_output_inputs();
        if target.memory_control(&command) || target.cursor_read(&command) {
            return Self::from_vfs(vfs, target, command).exclusive().run();
        }
        if matches!(command, FileCommand::Copy { .. } | FileCommand::Transfer(_)) {
            return Self::from_vfs(vfs, target, command).exclusive().run();
        }
        if matches!(command, FileCommand::SyncAll | FileCommand::SyncFilesystem) {
            return Self::from_vfs(vfs, target, command).run();
        }
        if target.regular_file()
            && !target.daemon_backed()
            && matches!(
                command,
                FileCommand::Write { .. }
                    | FileCommand::WriteSync { .. }
                    | FileCommand::Sync { .. }
                    | FileCommand::SyncRange { .. }
                    | FileCommand::Truncate(_)
                    | FileCommand::TruncateOpen
                    | FileCommand::Allocate { .. }
                    | FileCommand::Seals(Some(_))
            )
        {
            // This entry owns joined VM views, as the original direct call did.
            // A later resource wait releases that authority before parking.
            return Self::from_vfs(vfs, target, command).exclusive().run();
        }
        if target.proc_memory_command(&command)
            || target.position_busy(&command)
            || target.daemon_backed()
            || command.daemon_backed()
        {
            return Self::from_vfs(vfs, target, command).run();
        }

        if let Some(result) = target.proc_read(&command) {
            return Self::proc_outcome(result, || Self::from_vfs(vfs, target, command));
        }
        let resource_scope = resource_io::Scope::enter();
        let result = command.execute_target(vfs, &target);
        if let Some(pending) = resource_scope.finish() {
            let mut work = Self::from_vfs(vfs, target, command);
            work.resource_wait = Some(pending.wait);
            work.exclusive = false;
            return FileOutcome::Waiting(work);
        }
        if result.as_ref().is_err_and(|e| e.0 == 11) && target.waits(&command) {
            return FileOutcome::Waiting(Self::from_vfs(vfs, target, command));
        }
        let signal = vfs.take_file_size_signal();
        let scratch = match &mut command {
            FileCommand::Write { bytes, .. } | FileCommand::WriteSync { bytes, .. } => {
                Some(std::mem::take(bytes))
            }
            _ => None,
        };
        FileOutcome::Complete(FileReply {
            resources: Default::default(),
            result,
            file_size_signal: signal,
            scratch,
        })
    }
    pub fn run_inline(
        paths: &PathQueries,
        target: FileTarget,
        command: FileCommand,
    ) -> FileOutcome {
        let memory = trames_memory::CgroupMemoryContext::capture();
        let _memory = memory.enter();
        let io = cgroup::IoContext::capture();
        let _io = io.enter();
        let scope = crate::output_resources::OutputScope::enter();
        let original = target.0.clone();
        Self::run_inline_inner(paths, target, command)
            .retain_file(Some(original))
            .retain_output(scope.finish())
    }
    fn run_inline_inner(
        paths: &PathQueries,
        target: FileTarget,
        mut command: FileCommand,
    ) -> FileOutcome {
        command.retain_output_inputs();
        if target.memory_control(&command) || target.cursor_read(&command) {
            return Self::new(paths, target, command).run();
        }
        if matches!(command, FileCommand::Copy { .. } | FileCommand::Transfer(_)) {
            return Self::new(paths, target, command).run();
        }
        if target.proc_memory_command(&command)
            || target.position_busy(&command)
            || target.regular_file()
                && matches!(
                    command,
                    FileCommand::Write { .. }
                        | FileCommand::WriteSync { .. }
                        | FileCommand::Sync { .. }
                        | FileCommand::SyncRange { .. }
                        | FileCommand::Truncate(_)
                        | FileCommand::TruncateOpen
                        | FileCommand::Allocate { .. }
                        | FileCommand::Seals(Some(_))
                )
        {
            return Self::new(paths, target, command).run();
        }
        if target.daemon_backed() || command.daemon_backed() {
            return Self::new(paths, target, command).run();
        }
        if let Some(result) = target.proc_read(&command) {
            return Self::proc_outcome(result, || Self::new(paths, target, command));
        }
        let resource_scope = resource_io::Scope::enter();
        let reply = paths.file_command(&target, &command, false);
        if let Some(pending) = resource_scope.finish() {
            let mut work = Self::new(paths, target, command);
            work.resource_wait = Some(pending.wait);
            return FileOutcome::Waiting(work);
        }
        match reply {
            Some((result, signal)) => {
                if result.as_ref().is_err_and(|e| e.0 == 11) && target.waits(&command) {
                    return FileOutcome::Waiting(Self::new(paths, target, command));
                }
                let scratch = match &mut command {
                    FileCommand::Write { bytes, .. } | FileCommand::WriteSync { bytes, .. } => {
                        Some(std::mem::take(bytes))
                    }
                    _ => None,
                };
                FileOutcome::Complete(FileReply {
                    resources: Default::default(),
                    result,
                    file_size_signal: signal,
                    scratch,
                })
            }
            None if command
                .transfer_io(transfer_io::Io::blocked)
                .unwrap_or(false) =>
            {
                FileOutcome::Waiting(Self::new(paths, target, command))
            }
            None => Self::new(paths, target, command).defer_operation(),
        }
    }
    pub fn layout_domains(&self) -> Vec<u64> {
        let mut domains = self
            .target
            .as_ref()
            .map_or_else(Vec::new, FileTarget::layout_domains);
        if let Some(child) = self.command.transfer_io(transfer_io::Io::layout_domains) {
            domains.extend(child);
        }
        domains.sort_unstable();
        domains.dedup();
        domains
    }
    pub fn target(&self) -> Option<&FileTarget> {
        self.target.as_ref()
    }
    pub fn exclusive(mut self) -> Self {
        self.exclusive = true;
        self
    }
    pub fn begin_layout(&self) -> Option<trames_memory::layout::LayoutWrite> {
        self.admission_layout().map(|layout| layout.write())
    }
    pub fn admission_layout(&self) -> Option<Arc<trames_memory::layout::Layout>> {
        self.command
            .transfer_io(transfer_io::Io::layout)
            .flatten()
            .or_else(|| {
                self.fuse_layout
                    .clone()
                    .or_else(|| self.target.as_ref()?.layout())
            })
    }
    pub fn enter_layout(mut self, exclusive: trames_memory::layout::LayoutExclusive) -> Self {
        let original = self.admission_layout().expect("mapped original inode");
        assert!(
            Arc::ptr_eq(&original, exclusive.layout()),
            "original layout admission"
        );
        self.exclusive = true;
        self.layout_exclusive = Some(exclusive);
        self
    }
    fn proc_memory_step(&mut self) -> Option<Result<Option<FileValue>>> {
        let target = self.target.as_ref()?;
        if !target.proc_memory_command(&self.command) {
            return None;
        }
        let open = &target.0.open;
        let file = open.runtime_file.as_ref().unwrap();
        if self.proc_memory.is_none() {
            let (writing, requested, offset) = match &self.command {
                FileCommand::Read { count, offset } => (false, *count, *offset),
                FileCommand::Write { bytes, offset }
                | FileCommand::WriteSync { bytes, offset, .. } => (true, bytes.len(), *offset),
                _ => unreachable!(),
            };
            if writing && !fd_can_write(open.flags.get())
                || !writing && !fd_can_read(open.flags.get())
            {
                return Some(Err(Errno(9)));
            }
            if requested == 0 || !file.memory_alive() {
                return Some(Ok(Some(if writing {
                    FileValue::Count(0)
                } else {
                    FileValue::Bytes(Vec::new())
                })));
            }
            let mut state = open.file_position.lock().unwrap();
            if offset.is_none() && state.pending != 0 {
                return Some(Ok(None));
            }
            let address = offset.unwrap_or(state.value);
            let position = if offset.is_none() {
                state.pending += 1;
                Some(Arc::new(ProcPosition {
                    _file: target.0.clone(),
                    position: open.file_position.clone(),
                    offset: address,
                    committed: AtomicUsize::new(0),
                }))
            } else {
                None
            };
            self.proc_memory = Some(Box::new(ProcMemory {
                request: None,
                position,
                address,
                writing,
                requested,
                expected: 0,
                done: 0,
                output: Vec::new(),
            }));
        }
        let io = self.proc_memory.as_mut().unwrap();
        if let Some(request) = &io.request {
            let Some(result) = request.take() else {
                return Some(Ok(None));
            };
            io.request = None;
            let data = match result {
                Ok(data) => data,
                Err(trames_memory::TransferError::Retired) => return Some(Ok(Some(io.value()))),
                Err(_) if io.done != 0 => return Some(Ok(Some(io.value()))),
                Err(_) => return Some(Err(Errno(5))),
            };
            let n = data.len();
            io.done += n;
            if !io.writing {
                io.output.extend(data);
            }
            if n < io.expected || io.done == io.requested {
                return Some(Ok(Some(io.value())));
            }
        }
        let Some(remote) = file.memory_target() else {
            return Some(Err(Errno(95)));
        };
        let Some(address) = io.address.checked_add(io.done as u64) else {
            return Some(if io.done == 0 {
                Err(Errno(5))
            } else {
                Ok(Some(io.value()))
            });
        };
        io.expected = (io.requested - io.done).min(trames_memory::TRANSFER_WINDOW);
        let request = if io.writing {
            let bytes = match &self.command {
                FileCommand::Write { bytes, .. } | FileCommand::WriteSync { bytes, .. } => bytes,
                _ => unreachable!(),
            };
            let done = io.done;
            let completion = io.position.as_ref().map(|p| {
                let p = p.clone();
                Box::new(move |n| {
                    if let Some(n) = n {
                        p.record(done + n);
                    }
                }) as Box<dyn Fn(Option<usize>) + Send + Sync>
            });
            remote.submit_forced_write(
                address,
                bytes[done..done + io.expected].to_vec(),
                completion,
            )
        } else {
            remote.submit_forced_read(address, io.expected)
        };
        match request {
            Ok(request) => {
                io.request = Some(request);
                Some(Ok(None))
            }
            Err(trames_memory::TransferError::Retired) => Some(Ok(Some(io.value()))),
            Err(_) if io.done != 0 => Some(Ok(Some(io.value()))),
            Err(_) => Some(Err(Errno(5))),
        }
    }
    pub fn run(self) -> FileOutcome {
        let _memory = self.memory.enter();
        let _io = self.io.enter();
        let scope = crate::output_resources::OutputScope::enter();
        let original = self.target.as_ref().map(|target| target.0.clone());
        let mut outcome = self.run_inner();
        if let FileOutcome::Waiting(work) = &mut outcome {
            if work.resource_wait.is_some()
                || work
                    .command
                    .transfer_io(transfer_io::Io::retained)
                    .unwrap_or(false)
                || work.fuse_layout.take().is_some()
            {
                work.fuse_layout = None;
                work.layout_exclusive = None;
                work.exclusive = false;
            }
        }
        outcome.retain_file(original).retain_output(scope.finish())
    }
    fn run_inner(mut self) -> FileOutcome {
        if self
            .resource_wait
            .as_ref()
            .is_some_and(|wait| !wait.ready())
        {
            return FileOutcome::Waiting(self);
        }
        // A ready receipt can own cold copy-up progress. Keep it through an
        // intervening layout/owner handoff; a new wait replaces it only after
        // the actual resource body has resumed. Ready receipts do not override
        // other readiness or subscription sources above.
        if self.resource_open.is_some() {
            return self.run_resource_open();
        }
        if self
            .command
            .transfer_io(transfer_io::Io::owner)
            .unwrap_or(false)
        {
            return FileOutcome::Owner(self);
        }
        if self.sync_targets.is_none()
            && self.fuse_stat.is_none()
            && (matches!(self.command, FileCommand::SyncAll)
                || matches!(self.command, FileCommand::SyncFilesystem)
                    && self
                        .target
                        .as_ref()
                        .is_some_and(|target| target.status_flags() & O_PATH == 0))
        {
            self = self.queued();
        }
        self.command.retain_output_inputs();
        if !self.exclusive {
            let layout = if let Some(metadata) = &self.fuse_stat {
                if !metadata.ready() {
                    return FileOutcome::Waiting(self);
                }
                metadata.layout()
            } else {
                self.target
                    .as_ref()
                    .and_then(|target| match &target.0.open.control {
                        Some(events::SharedControl::FuseFile(file)) => file.mapped_layout(),
                        _ => None,
                    })
            };
            if let Some(layout) = layout {
                self.fuse_layout = Some(layout);
                return FileOutcome::Layout(self);
            }
        }
        if let Some(result) = self.proc_memory_step() {
            return match result {
                Ok(None) => FileOutcome::Waiting(self),
                result => FileOutcome::Complete(FileReply {
                    resources: Default::default(),
                    result: result.map(Option::unwrap),
                    file_size_signal: false,
                    scratch: None,
                }),
            };
        }
        if self.read.is_none()
            && self.write.is_none()
            && self.memory_control.is_none()
            && self
                .target
                .as_ref()
                .is_some_and(|t| t.position_busy(&self.command))
        {
            return FileOutcome::Waiting(self);
        }

        if let Some(wait) = &self.linger {
            return if wait.ready() {
                FileOutcome::Complete(FileReply {
                    resources: Default::default(),
                    result: Ok(FileValue::Count(0)),
                    file_size_signal: false,
                    scratch: None,
                })
            } else {
                FileOutcome::Waiting(self)
            };
        }
        if self
            .fuse_stat
            .as_ref()
            .is_some_and(|pending| pending.owner_work())
        {
            return FileOutcome::Owner(self);
        }
        if let Some(p) = &mut self.fuse_stat {
            let value = p.take(&mut self.paths.view.borrow_mut());
            if self.write.is_some() || self.sync.is_some() || self.mutation.is_some() {
                return match value {
                    Some(Ok(_)) => {
                        self.fuse_stat = None;
                        self.run_inner()
                    }
                    Some(Err(error)) if self.write.is_some() => self.fail_write(error),
                    Some(Err(error)) => FileOutcome::Complete(Self::descriptor_result(
                        Err(error),
                        &mut self.command,
                    )),
                    None => FileOutcome::Waiting(self),
                };
            }
            if self
                .command
                .transfer_io(transfer_io::Io::pending)
                .unwrap_or(false)
            {
                let Some(value) = value else {
                    return FileOutcome::Waiting(self);
                };
                self.command.complete_transfer_io(value);
                self.fuse_stat = None;
                // One copy can cross different mapped source/target inodes.
                // Admission for a completed step cannot authorize the next one.
                self.layout_exclusive = None;
                self.fuse_layout = None;
                self.exclusive = false;
                return self.run_inner();
            }
            if matches!(&value, Some(Err(_))) {
                let open = {
                    let view = self.paths.view.borrow();
                    let query = view.query.as_ref().unwrap();
                    query
                        .take_deferred()
                        .then(|| query.prepared.borrow_mut().open.take())
                        .flatten()
                };
                if let Some(open) = open {
                    if let FileCommand::Truncate(length) = self.command {
                        // A daemon symlink/magic link reached an ordinary file.
                        // Keep its accepted inode, drop the unused reservation,
                        // and enter the ordinary layout-aware truncate path.
                        let mut next = FileWork::new(
                            &self.paths,
                            open.target.clone(),
                            FileCommand::Truncate(length),
                        );
                        if let Some(pending) = self.fuse_stat.take().filter(|p| p.retry_armed()) {
                            next.path_retry = Some(Box::new(PathRevalidation {
                                paths: self.paths,
                                pending,
                            }));
                        }
                        return next.run();
                    }
                    let mut next =
                        FileWork::new(&self.paths, open.target.clone(), FileCommand::TruncateOpen);
                    next.open = Some(Box::new(open));
                    if let Some(pending) = self.fuse_stat.take().filter(|p| p.retry_armed()) {
                        next.path_retry = Some(Box::new(PathRevalidation {
                            paths: self.paths,
                            pending,
                        }));
                    }
                    return next.run();
                }
            }
            if value.as_ref().is_some_and(FileResources::needed) {
                p.retain_output();
            }
            if matches!(
                self.command,
                FileCommand::SyncAll | FileCommand::SyncFilesystem
            ) && self.sync_targets.is_some()
                && matches!(&value, Some(Ok(_)))
            {
                self.fuse_stat = None;
                return self.run_inner();
            }
            return match value {
                Some(result) => FileOutcome::Complete(FileReply {
                    resources: Default::default(),
                    result,
                    file_size_signal: self.paths.view.borrow().take_file_size_signal(),
                    scratch: None,
                }),
                None => FileOutcome::Waiting(self),
            };
        }
        if let Some(target) = &self.target {
            if let (
                Some(events::SharedControl::Fuse(device)),
                FileCommand::Write { bytes, .. } | FileCommand::WriteSync { bytes, .. },
            ) = (&target.0.open.control, &self.command)
            {
                let pending = if fd_can_write(target.0.open.flags.get()) {
                    device.notification(&self.paths.view.borrow(), bytes)
                } else {
                    Err(Errno(9))
                };
                match pending {
                    Ok(Some(pending)) => {
                        self.fuse_stat = Some(Box::new(pending));
                        return FileOutcome::Waiting(self);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        return FileOutcome::Complete(FileReply {
                            resources: Default::default(),
                            result: Err(error),
                            file_size_signal: false,
                            scratch: None,
                        })
                    }
                }
            }
            if let Some(events::SharedControl::FuseFile(file)) =
                target.0.open.control.as_ref().filter(|_| {
                    !matches!(
                        self.command,
                        FileCommand::SyncFilesystem
                            | FileCommand::Copy { .. }
                            | FileCommand::Transfer(_)
                    )
                })
            {
                if let FileCommand::Seek { offset, whence } = self.command {
                    return match file.seek(&target.0.open.file_position, offset, whence) {
                        Ok(None) => FileOutcome::Waiting(self),
                        result => FileOutcome::Complete(FileReply {
                            resources: Default::default(),
                            result: result.map(|value| FileValue::Count(value.unwrap())),
                            file_size_signal: false,
                            scratch: None,
                        }),
                    };
                }
                let pending = if matches!(
                    self.command,
                    FileCommand::Truncate(_) | FileCommand::TruncateOpen
                ) && target.0.open.landlock_denied & landlock::TRUNCATE != 0
                {
                    Err(Errno(13))
                } else {
                    file.operation(&self.paths.view.borrow(), &self.command, &target.0)
                };
                return match pending {
                    Ok(op) => {
                        self.fuse_stat = op.map(Box::new);
                        if self.fuse_stat.as_ref().is_some_and(|pending| {
                            pending.daemon_request().is_none() && pending.ready()
                        }) {
                            self.run_inner()
                        } else {
                            FileOutcome::Waiting(self)
                        }
                    }
                    Err(error) => FileOutcome::Complete(FileReply {
                        resources: Default::default(),
                        result: Err(error),
                        file_size_signal: self.paths.view.borrow().take_file_size_signal(),
                        scratch: None,
                    }),
                };
            }
        }
        if let Some(result) = self
            .target
            .as_ref()
            .and_then(|target| target.proc_read(&self.command))
        {
            return Self::proc_outcome(result, || self);
        }
        if let Some(namespace) = &mut self.namespace {
            return match namespace.run(&self.paths) {
                namespace_work::NamespaceRun::Complete(result) => {
                    FileOutcome::Complete(FileReply {
                        resources: Default::default(),
                        result,
                        file_size_signal: false,
                        scratch: None,
                    })
                }
                namespace_work::NamespaceRun::Owner => FileOutcome::Owner(self),
                namespace_work::NamespaceRun::Waiting => FileOutcome::Waiting(self),
            };
        }
        if self.memory_control.is_some()
            || self
                .target
                .as_ref()
                .is_some_and(|target| target.memory_control(&self.command))
        {
            return self.run_memory_control();
        }
        if self.read.is_some()
            || self
                .target
                .as_ref()
                .is_some_and(|target| target.cursor_read(&self.command))
        {
            return self.run_read();
        }
        if self.mutation.is_some() || self.cursor_resize() {
            return self.run_resize();
        }
        if self.sync.is_some() || self.cursor_sync() {
            return self.run_sync();
        }
        if self.write.is_some() || self.cursor_write() {
            return self.run_write();
        }
        let resource_scope = resource_io::Scope::enter();
        let reply = if let Some(targets) = &mut self.sync_targets {
            Some((
                targets
                    .iter_mut()
                    .try_for_each(storage::FilesystemSync::run)
                    .map(|()| FileValue::Count(0)),
                false,
            ))
        } else if let Some(target) = &self.target {
            self.paths
                .file_command(target, &self.command, self.exclusive)
        } else {
            Some((
                self.paths
                    .view
                    .borrow()
                    .sync()
                    .map(|()| FileValue::Count(0)),
                false,
            ))
        };
        if let Some(pending) = resource_scope.finish() {
            self.resource_wait = Some(pending.wait);
            return FileOutcome::Waiting(self);
        }
        if reply.is_none() {
            return self.defer_operation();
        }
        match reply {
            Some((mut result, signal)) => {
                if matches!(result, Err(Errno(116))) {
                    if let Some(mut original) = self.path_retry.take() {
                        let slot = self.open.take().map(|open| open.reservation);
                        if original.pending.native_stale(slot) {
                            let mut next = FileWork::sync_all(*original.paths);
                            next.command =
                                std::mem::replace(&mut self.command, FileCommand::SyncAll);
                            next.fuse_stat = Some(original.pending);
                            // Release the failed native OFD, writer and layout
                            // admission before rewalking the original pathname.
                            drop(self);
                            return next.run();
                        }
                    }
                }
                if result.as_ref().is_err_and(|e| e.0 == 11)
                    && (self.console_wait().is_some()
                        || self.waiting()
                        || self.target.as_ref().is_some_and(|target| {
                            matches!(self.command, FileCommand::Read { offset: None, .. })
                                && target.position_command(&self.command)
                        }))
                {
                    return FileOutcome::Waiting(self);
                }
                result = self.publish_open(result);
                let scratch = match &mut self.command {
                    FileCommand::Write { bytes, .. } | FileCommand::WriteSync { bytes, .. } => {
                        Some(std::mem::take(bytes))
                    }
                    _ => None,
                };
                FileOutcome::Complete(FileReply {
                    resources: Default::default(),
                    result,
                    file_size_signal: signal,
                    scratch,
                })
            }
            None => FileOutcome::Layout(self),
        }
    }
    fn defer_operation(mut self) -> FileOutcome {
        if self
            .command
            .transfer_io(transfer_io::Io::owner)
            .unwrap_or(false)
        {
            return FileOutcome::Owner(self);
        }
        let pending = self
            .paths
            .view
            .borrow()
            .query
            .as_ref()
            .unwrap()
            .prepared
            .borrow_mut()
            .fuse
            .take();
        if let Some(pending) = pending {
            // Keep original daemon metadata even when the accepted descriptor
            // itself has no FUSE handle; retries must not submit it again.
            self.fuse_stat = Some(pending);
            FileOutcome::Waiting(self)
        } else if self
            .command
            .transfer_io(transfer_io::Io::blocked)
            .unwrap_or(false)
        {
            FileOutcome::Waiting(self)
        } else {
            FileOutcome::Layout(self)
        }
    }
}
impl PathQueries {
    pub fn fuse_file_work(&self, fd: u32, command: FileCommand) -> Option<Result<FileWork>> {
        let view = self.view.borrow();
        let descriptor = match view.descriptor(fd) {
            Ok(descriptor) => descriptor,
            Err(error) => return Some(Err(error)),
        };
        if !matches!(
            descriptor.open.borrow().control,
            Some(events::SharedControl::FuseFile(_) | events::SharedControl::Fuse(_))
        ) {
            return None;
        }
        let target = SharedFd::new(descriptor.open.borrow().shared.clone()).filesystem_target();
        Some(Ok(FileWork::from_vfs(&view, target, command)))
    }
    pub fn truncate_path_work(&self, path: &[u8], length: u64) -> Option<Result<FileWork>> {
        if length > i64::MAX as u64 {
            return Some(Err(Errno(22)));
        }
        let mut view = self.view.borrow_mut();
        view.query.as_ref().unwrap().clear_deferred();
        let result = view
            .resolve_entry_operation(
                AT_FDCWD,
                path,
                true,
                true,
                0,
                true,
                Some(ResolveOperation::Fuse(fuse::PathOperation::Truncate(
                    length,
                ))),
                None,
            )
            .and_then(|entry| {
                let result = view.prepare_path_truncate(entry, length);
                fuse::PathRetry::arm(
                    &view,
                    AT_FDCWD,
                    path,
                    true,
                    true,
                    0,
                    true,
                    fuse::PathOperation::Truncate(length),
                    None,
                    true,
                );
                result
            });
        let query = view.query.as_ref().unwrap();
        let accepted = query.prepared.borrow_mut().open.take();
        if let Some(open) = accepted {
            // The resolver owns the original OFD before any numeric publication.
            // Release only this hidden reservation; FD reuse cannot retarget it.
            return Some(Ok(FileWork::from_vfs(
                &view,
                open.target.clone(),
                FileCommand::Truncate(length),
            )));
        }
        let pending = {
            let mut prepared = query.prepared.borrow_mut();
            prepared
                .fuse
                .take()
                .or_else(|| {
                    prepared
                        .owner_continuation
                        .take()
                        .map(|walk| Box::new(fuse::Metadata::continuation(&view, walk, true)))
                })
                .or_else(|| {
                    prepared
                        .continuation
                        .take()
                        .map(|walk| Box::new(fuse::Metadata::continuation(&view, walk, false)))
                })
        };
        if let Some(pending) = pending {
            query.take_deferred();
            drop(view);
            let mut work = FileWork::sync_all(self.retain_context());
            work.command = FileCommand::Truncate(length);
            work.fuse_stat = Some(pending);
            return Some(Ok(work));
        }
        if query.take_deferred() {
            None
        } else {
            Some(result.map(|_| unreachable!("captured shared open")))
        }
    }
    /// The path resolver has already accepted the original inode and reserved
    /// its unpublished FD. No pathname/input lookup is repeated after waiting.
    pub fn close_file(
        &self,
        files: &SharedFiles,
        fd: u32,
        owner: u32,
    ) -> Option<Result<Option<FileWork>>> {
        Some(files.close_slot(fd, owner)?.and_then(|slot| {
            let Some(Ok(open)) = slot.shared_open() else {
                return Ok(None);
            };
            if open.socket.is_some() {
                // Consume the removed descriptor outside Files. A dup, fork or
                // in-flight operation holding the OFD keeps the stream open.
                let fd_table::SlotOpen::Shared(open) = slot.open else {
                    unreachable!()
                };
                let Some(mut open) = Arc::into_inner(open) else {
                    return Ok(None);
                };
                let Some(wait) = open
                    .socket
                    .take()
                    .and_then(Arc::into_inner)
                    .and_then(NetSocket::into_linger)
                else {
                    return Ok(None);
                };
                let mut work = FileWork::sync_all(self.retain_context());
                work.linger = Some(Box::new(wait));
                return Ok(Some(work));
            }
            let Some(events::SharedControl::FuseFile(file)) = &open.control else {
                return Ok(None);
            };
            let Some(flush) = file.flush(&self.view.borrow())? else {
                return Ok(None);
            };
            let mut work = FileWork::sync_all(self.retain_context());
            work.fuse_stat = Some(Box::new(flush));
            Ok(Some(work))
        }))
    }
    pub fn take_fuse_stat(&self) -> Option<FileWork> {
        if let Some(work) = self
            .view
            .borrow()
            .query
            .as_ref()?
            .prepared
            .borrow_mut()
            .work
            .take()
        {
            return Some(work.into_inner().unwrap());
        }
        let pending = self
            .view
            .borrow()
            .query
            .as_ref()?
            .prepared
            .borrow_mut()
            .fuse
            .take()?;
        let mut work = FileWork::sync_all(self.retain_context());
        work.fuse_stat = Some(pending);
        Some(work)
    }
    pub fn take_open_work(&self) -> Option<FileWork> {
        if let Some(work) = self.take_fuse_stat() {
            return Some(work);
        }
        let open = self
            .view
            .borrow()
            .query
            .as_ref()?
            .prepared
            .borrow_mut()
            .open
            .take()?;
        let mut work = FileWork::new(self, open.target.clone(), FileCommand::TruncateOpen);
        work.open = Some(Box::new(open));
        Some(work)
    }
    fn file_context(&self, target: &FileTarget, command: &FileCommand) -> Self {
        let original = self.view.borrow();
        Self::file_view(&original, target, command)
    }
    fn file_view(original: &Vfs, target: &FileTarget, command: &FileCommand) -> Self {
        let retained = target.0.clone().retained();
        let open = retained.0.open.borrow();
        // This typed FD operation needs its original filesystem/credentials,
        // not a clone of the task's pathname/mount/pseudo control namespace.
        let fs = open
            .mount
            .as_ref()
            .map_or(&original.fs, |mount| &mount.fs)
            .clone();
        let mut view = Vfs::empty(fs);
        if open.mount_file.is_some() {
            view.cgroup_namespace = original.cgroup_namespace.clone();
        }
        if matches!(open.sysctl_control, Some(sysctl::Control::UtsName(..))) {
            view.uts = original.uts.clone();
        }
        view.pid = original.pid;
        if matches!(open.control, Some(events::SharedControl::FuseFile(_)))
            || command.daemon_backed()
            || open
                .mount
                .as_ref()
                .is_some_and(|mount| mount.fs.fuse.is_some())
        {
            view.pid_ns = original.pid_ns.clone();
        }
        view.lock_owner = original.lock_owner;
        view.credentials = original.credentials.clone();
        view.file_size_limit = original.file_size_limit.clone();
        view.query = Some(original.query.as_ref().map_or_else(
            || path_queries::Authority::file_root(original),
            path_queries::Authority::file_projection,
        ));
        Self {
            view: RefCell::new(view),
        }
    }
    fn file_command(
        &self,
        target: &FileTarget,
        command: &FileCommand,
        exclusive: bool,
    ) -> Option<(Result<FileValue>, bool)> {
        self.file_operation(exclusive, |view| command.execute_target(view, target))
    }
    fn file_operation(
        &self,
        exclusive: bool,
        operation: impl FnOnce(&mut Vfs) -> Result<FileValue>,
    ) -> Option<(Result<FileValue>, bool)> {
        let mut view = self.view.borrow_mut();
        let authority = view.query.as_mut().expect("sealed file authority");
        authority.file_layout_exclusive = exclusive;
        authority.clear_deferred();
        view.file_size_signal.set(false);
        let result = operation(&mut view);
        let signal = view.file_size_signal.replace(false);
        let authority = view.query.as_ref().unwrap();
        (!authority.take_deferred()).then_some((result, signal))
    }
}
impl Vfs {
    /// One accepted pathname entry. FUSE needs SETATTR, not a temporary daemon
    /// OPEN or an FD slot. Ordinary files retain their existing layout-aware
    /// FileWork path and hidden OFD; no name is replayed after a daemon wait.
    pub(super) fn prepare_path_truncate(
        &mut self,
        entry: ResolvedEntry,
        length: u64,
    ) -> Result<u32> {
        let target = self.metadata_target_resolved(entry.clone())?;
        if let Some((mount, fs)) = target
            .path
            .mount
            .as_ref()
            .and_then(|m| m.fs.fuse.as_ref().map(|fs| (m, fs)))
        {
            if self.landlock_denied(&target.path, Some(&target.node), landlock::TRUNCATE)? != 0 {
                return Err(Errno(13));
            }
            let operation = fuse::Metadata::path_size(
                self,
                &mount.shared,
                fs,
                target.node.clone(),
                length,
                self.event_link(&target.path, &target.node),
            )?;
            let query = self.query.as_ref().ok_or(Errno(95))?;
            query.prepared.borrow_mut().fuse = Some(Box::new(operation));
            return query.defer();
        }
        let files = self
            .query
            .as_ref()
            .map_or_else(|| self.shared_files(), |q| q.files.clone());
        let reservation = files.reserve()?;
        self.open_resolved::<true>(entry, 1, 0, None, reservation)
    }
}

impl FileCommand {
    fn daemon_backed(&self) -> bool {
        match self {
            Self::Copy { input, .. } => input.daemon_backed(),
            Self::Transfer(transfer) => transfer.lock().unwrap().daemon_backed(),
            _ => false,
        }
    }
    fn transfer_io<T>(&self, f: impl FnOnce(&transfer_io::Io) -> T) -> Option<T> {
        match self {
            Self::Copy { transfer, .. } => Some(f(&transfer.lock().unwrap().io)),
            Self::Transfer(transfer) => Some(f(&transfer.lock().unwrap().io)),
            _ => None,
        }
    }
    fn transfer_io_mut<T>(&mut self, f: impl FnOnce(&mut transfer_io::Io) -> T) -> Option<T> {
        match self {
            Self::Copy { transfer, .. } => Some(f(&mut transfer.lock().unwrap().io)),
            Self::Transfer(transfer) => Some(f(&mut transfer.lock().unwrap().io)),
            _ => None,
        }
    }
    fn complete_transfer_io(&self, value: Result<FileValue>) {
        match self {
            Self::Copy { transfer, .. } => transfer.lock().unwrap().io.complete(value),
            Self::Transfer(transfer) => transfer.lock().unwrap().io.complete(value),
            _ => unreachable!("accepted transfer reply"),
        }
    }
    fn retain_output_inputs(&self) {
        match self {
            Self::Copy { input, .. } => {
                crate::output_resources::OutputScope::retain(|| input.0.clone())
            }
            Self::Transfer(transfer) => crate::output_resources::OutputScope::retain(|| {
                let transfer = transfer.lock().unwrap();
                (transfer.input.clone(), transfer.output.clone())
            }),
            _ => {}
        }
    }
    /// Data operations use the accepted OFD directly. In particular, a short
    /// joined call does not allocate/swap a private files_struct just to reach
    /// the same resource, and close/reuse cannot retarget an accepted call.
    fn execute_target(&self, v: &mut Vfs, target: &FileTarget) -> Result<FileValue> {
        if let Some(console) = target.0.open.console.get() {
            let flags = target.0.open.flags.get();
            match self {
                Self::Read {
                    count,
                    offset: None,
                } => {
                    if !fd_can_read(flags) {
                        return Err(Errno(9));
                    }
                    return console.read(*count).map(FileValue::Bytes);
                }
                Self::Write {
                    bytes,
                    offset: None,
                } => {
                    if !fd_can_write(flags) {
                        return Err(Errno(9));
                    }
                    return console.write(bytes).map(|n| FileValue::Count(n as u64));
                }
                _ => {}
            }
        }
        let descriptor = Descriptor {
            open: OpenHandle::Shared(target.0.open.clone()),
            cloexec: false.into(),
        };
        match self {
            Self::Seals(add) => Vfs::seals_description(&descriptor, *add)
                .map(|value| FileValue::Count(value as u64)),
            Self::Transfer(transfer) => transfer.lock().unwrap().execute(v),
            Self::Read {
                count,
                offset: None,
            } if *count != 0 && target.positioned_read() => {
                if !fd_can_read(target.0.open.flags.get()) {
                    return Err(Errno(9));
                }
                let position = crate::read_reply::FileRead::begin(target.0.clone())?;
                v.pread_description(&descriptor, *count, position.offset)
                    .map(|bytes| FileValue::Read(ReadReply::new(bytes, position)))
            }
            Self::Read {
                count,
                offset: None,
            } => v
                .read_description(&descriptor, *count)
                .map(FileValue::Bytes),
            Self::Read {
                count,
                offset: Some(offset),
            } => {
                if *offset > i64::MAX as u64 && !target.unsigned_offsets() {
                    return Err(Errno(22));
                }
                v.pread_description(&descriptor, *count, *offset)
                    .map(FileValue::Bytes)
            }
            Self::Write { bytes, offset } | Self::WriteSync { bytes, offset, .. } => {
                if offset.is_some_and(|offset| offset > i64::MAX as u64)
                    && !target.unsigned_offsets()
                {
                    return Err(Errno(22));
                }
                let count = if let Self::WriteSync { data_only, .. } = self {
                    v.file_write_sync_description(&descriptor, bytes, *offset, *data_only)?
                } else {
                    v.file_write_description(&descriptor, bytes, *offset)?
                };
                Ok(FileValue::Count(count as u64))
            }
            Self::Seek { offset, whence } => {
                Vfs::seek_description(&descriptor, *offset, *whence).map(FileValue::Count)
            }
            Self::Sync { data_only } => v
                .sync_description(&descriptor, *data_only)
                .map(|()| FileValue::Count(0)),
            _ => {
                let retained = target.0.clone().retained();
                v.with_uring_fd(&retained, |v, fd| self.execute(v, fd))
            }
        }
    }
    fn execute(&self, v: &mut Vfs, fd: u32) -> Result<FileValue> {
        match self {
            FileCommand::Transfer(transfer) => transfer.lock().unwrap().execute(v),
            FileCommand::ReadDirectory { count } => v.getdents(fd, *count).map(FileValue::Bytes),
            FileCommand::Copy { input, transfer } => v.with_file_peer(input, |v, input| {
                transfer.lock().unwrap().execute(v, input, fd)
            }),
            FileCommand::Seek { offset, whence } => {
                v.seek(fd, *offset, *whence).map(FileValue::Count)
            }
            FileCommand::Stat => v.stat_fd(fd).map(FileValue::Stat),
            FileCommand::Read {
                count,
                offset: None,
            } => v.read(fd, *count).map(FileValue::Bytes),
            FileCommand::Read {
                count,
                offset: Some(offset),
            } => v.pread(fd, *count, *offset).map(FileValue::Bytes),
            FileCommand::Write {
                bytes,
                offset: None,
            } => v.write(fd, bytes).map(|n| FileValue::Count(n as u64)),
            FileCommand::Write {
                bytes,
                offset: Some(offset),
            } => v
                .pwrite(fd, bytes, *offset)
                .map(|n| FileValue::Count(n as u64)),
            FileCommand::WriteSync {
                bytes,
                offset,
                data_only,
            } => {
                let descriptor = v.descriptor(fd)?;
                let ordinary = descriptor
                    .open
                    .borrow()
                    .node
                    .as_ref()
                    .is_some_and(|node| matches!(node.borrow().content, Content::File(_)));
                if ordinary {
                    if offset.is_some_and(|offset| offset > i64::MAX as u64) {
                        return Err(Errno(22));
                    }
                    return v
                        .file_write_sync_description(&descriptor, bytes, *offset, *data_only)
                        .map(|count| FileValue::Count(count as u64));
                }
                let n = if let Some(offset) = offset {
                    v.pwrite(fd, bytes, *offset)?
                } else {
                    v.write(fd, bytes)?
                };
                v.sync_fd(fd, *data_only)?;
                Ok(FileValue::Count(n as u64))
            }
            FileCommand::Truncate(length) => {
                v.truncate_fd(fd, *length).map(|()| FileValue::Count(0))
            }
            FileCommand::TruncateOpen => v.truncate_open(fd).map(|()| FileValue::Count(0)),
            FileCommand::Allocate {
                mode,
                offset,
                length,
            } => v
                .allocate_fd(fd, *mode, *offset, *length)
                .map(|()| FileValue::Count(0)),
            FileCommand::Sync { data_only } => {
                v.sync_fd(fd, *data_only).map(|()| FileValue::Count(0))
            }
            FileCommand::Seals(add) => v
                .seals(fd, *add)
                .map(|value| FileValue::Count(value as u64)),
            FileCommand::SyncRange {
                offset,
                length,
                flags,
            } => v
                .sync_file_range(fd, *offset, *length, *flags)
                .map(|()| FileValue::Count(0)),
            FileCommand::SyncAll => v.sync().map(|()| FileValue::Count(0)),
            FileCommand::SyncFilesystem => v.sync_filesystem_fd(fd).map(|()| FileValue::Count(0)),
        }
    }
}

/// Retains explicit ABI offsets and bytes across an actual output-layout wait.
/// An accepted input is never reread after another writer changes that file.
pub struct FileCopy {
    pub from: Result<Option<u64>>,
    pub to: Result<Option<u64>>,
    pub count: u64,
    pub range: bool,
    stage: Option<CopyStage>,
    copied: u64,
    io: transfer_io::Io,
    source_stat: Option<[u8; 128]>,
    target_stat: Option<[u8; 128]>,
    start_from: Option<u64>,
    start_to: Option<u64>,
    source_position: Option<transfer_io::Position>,
    output_position: Option<transfer_io::Position>,
    cancelled: bool,
}
struct CopyStage {
    from: u64,
    to: Option<u64>,
    bytes: Option<Vec<u8>>,
    written: Option<(usize, usize)>,
    source_committed: bool,
    output_committed: bool,
    offered: usize,
}
struct CancelledCopy {
    _io: transfer_io::Io,
    position: Option<transfer_io::Position>,
    output: Option<transfer_io::Position>,
    _stage: Option<CopyStage>,
    prefix_end: Option<u64>,
    output_end: Option<u64>,
    range: bool,
}
impl Drop for CancelledCopy {
    fn drop(&mut self) {
        drop(std::mem::take(&mut self._io));
        if let (Some(position), Some(end)) = (&self.position, self.prefix_end) {
            position.record(end);
        }
        if let (Some(position), Some(end)) = (&self.output, self.output_end) {
            position.record(end);
        }
        let source = self.position.take();
        let output = self.output.take();
        if self.range {
            drop(source);
            drop(output);
        } else {
            drop(output);
            drop(source);
        }
    }
}
impl Drop for FileCopy {
    fn drop(&mut self) {
        drop(self.cancel_pending());
    }
}
impl Vfs {
    pub const MAX_RW_COUNT: u64 = i32::MAX as u64 & !(trames_memory::PAGE_SIZE - 1);
    /// Linux rw_verify_area validates the requested range before EOF or append
    /// placement can shorten or redirect a transfer.
    pub fn check_io_range(offset: u64, count: u64) -> Result<()> {
        if offset
            .checked_add(count)
            .is_some_and(|end| end <= i64::MAX as u64)
        {
            Ok(())
        } else {
            Err(Errno(22))
        }
    }
    pub fn check_sendfile_modes(input: u32, output: u32) -> Result<()> {
        if !fd_can_read(input) || !fd_can_write(output) {
            return Err(Errno(9));
        }
        if output & 0x400 != 0 {
            return Err(Errno(22));
        }
        Ok(())
    }
    /// Linux copy_file_range validates the original unsigned range before EOF
    /// shortening. Both embedding and retained native I/O use this prelude.
    pub fn copy_file_range_length(
        source: &[u8; 128],
        target: &[u8; 128],
        from: u64,
        to: u64,
        count: u64,
    ) -> Result<u64> {
        for stat in [source, target] {
            let mode = u32::from_le_bytes(stat[16..20].try_into().expect("mode")) & 0o170000;
            if mode == 0o040000 {
                return Err(Errno(21));
            }
            if mode != 0o100000 {
                return Err(Errno(22));
            }
        }
        from.checked_add(count).ok_or(Errno(75))?;
        to.checked_add(count).ok_or(Errno(75))?;
        if from > i64::MAX as u64 || to > i64::MAX as u64 {
            return Err(Errno(22));
        }
        let size = u64::from_le_bytes(source[48..56].try_into().expect("size"));
        let count = count.min(size.saturating_sub(from));
        if source[..16] == target[..16]
            && from < to.saturating_add(count)
            && to < from.saturating_add(count)
        {
            return Err(Errno(22));
        }
        Ok(count)
    }
}
pub(super) fn repeat_tail(seed: &[u8], count: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(count);
    bytes.extend_from_slice(seed);
    while bytes.len() < count {
        let n = bytes.len().min(count - bytes.len());
        bytes.extend_from_within(..n);
    }
    bytes
}

impl FileCopy {
    fn cancel_pending(&mut self) -> CancelledCopy {
        self.cancelled = true;
        let prefix_end = self
            .stage
            .as_ref()
            .filter(|stage| !stage.source_committed)
            .and_then(|stage| {
                let count = stage
                    .written
                    .map_or_else(|| self.io.cancelled_write_progress(), |(count, _)| count);
                (count != 0).then(|| stage.from + count as u64)
            });
        CancelledCopy {
            output_end: self
                .stage
                .as_ref()
                .filter(|stage| !stage.output_committed)
                .and_then(|stage| {
                    let count = stage
                        .written
                        .map_or_else(|| self.io.cancelled_write_progress(), |(count, _)| count);
                    (count != 0).then(|| {
                        self.io.write_end().unwrap_or_else(|| {
                            self.output_position
                                .as_ref()
                                .map_or(0, |position| position.offset)
                                + self.copied
                                + count as u64
                        })
                    })
                }),
            _io: std::mem::take(&mut self.io),
            position: self.source_position.take(),
            output: self.output_position.take(),
            _stage: self.stage.take(),
            prefix_end,
            range: self.range,
        }
    }
    pub fn new(
        from: Result<Option<u64>>,
        to: Result<Option<u64>>,
        count: u64,
        range: bool,
    ) -> Self {
        Self {
            from,
            to,
            count,
            range,
            stage: None,
            copied: 0,
            io: Default::default(),
            source_stat: None,
            target_stat: None,
            start_from: None,
            start_to: None,
            source_position: None,
            output_position: None,
            cancelled: false,
        }
    }
    fn execute(&mut self, v: &mut Vfs, input: u32, output: u32) -> Result<FileValue> {
        if self.cancelled {
            return Err(Errno(4));
        }
        if self.stage.is_none() {
            if !self.range {
                Vfs::check_sendfile_modes(v.flags(input)?, v.flags(output)?)?;
            }
            if self.source_stat.is_none() {
                self.source_stat = Some(transfer_io::Io::stat(self.io.call(
                    &v.descriptor(input)?,
                    v,
                    FileCommand::Stat,
                    transfer_io::Step::SourceStat,
                )?)?);
            }
            let source = self.source_stat.unwrap();
            v.fd_kind(output)?;
            let from = if let Some(from) = self.start_from {
                from
            } else {
                let from = match self.from? {
                    Some(offset) => offset,
                    None => {
                        let descriptor = v.descriptor(input)?;
                        let file = SharedFd::new(descriptor.open.borrow().shared.clone());
                        if file.open.is_regular_file() {
                            file.open.file_position.snapshot()
                        } else {
                            self.io.seek(v, &descriptor, 0, 1)?
                        }
                    }
                };
                self.start_from = Some(from);
                from
            };
            let to = if self.range {
                if self.target_stat.is_none() {
                    self.target_stat = Some(transfer_io::Io::stat(self.io.call(
                        &v.descriptor(output)?,
                        v,
                        FileCommand::Stat,
                        transfer_io::Step::TargetStat,
                    )?)?);
                }
                let target = self.target_stat.unwrap();
                if v.flags(output)? & 0x400 != 0 {
                    return Err(Errno(9));
                }
                let offset = if let Some(to) = self.start_to {
                    to
                } else {
                    let to = match self.to? {
                        Some(offset) => offset,
                        None => v.descriptor(output)?.open.borrow().file_position.snapshot(),
                    };
                    self.start_to = Some(to);
                    to
                };
                self.count =
                    Vfs::copy_file_range_length(&source, &target, from, offset, self.count)?;
                Some(offset)
            } else {
                None
            };
            if !self.range {
                Vfs::check_io_range(from, self.count)?;
                if transfer_io::Io::regular(&SharedFd::new(
                    v.descriptor(output)?.open.borrow().shared.clone(),
                )) {
                    let offset = v.descriptor(output)?.open.borrow().file_position.snapshot();
                    self.start_to = Some(offset);
                    Vfs::check_io_range(offset, self.count.min(Vfs::MAX_RW_COUNT))?;
                }
            }
            self.start(from, to);
        }
        self.drive(v, input, output)
    }

    /// Joined ABI execution has already imported and validated both offsets.
    pub fn copy_prepared(
        mut self,
        v: &mut Vfs,
        input: u32,
        output: u32,
        from: u64,
        to: Option<u64>,
    ) -> Result<u64> {
        self.start(from, to);
        {
            let input = FileTarget(SharedFd::new(
                v.descriptor(input)?.open.borrow().shared.clone(),
            ));
            let target = FileTarget(SharedFd::new(
                v.descriptor(output)?.open.borrow().shared.clone(),
            ));
            let command = FileCommand::Copy {
                input,
                transfer: Arc::new(std::sync::Mutex::new(self)),
            };
            match v.transfer_work(FileWork::from_vfs(v, target, command))? {
                FileValue::Transfer { count, .. } => Ok(count),
                _ => unreachable!("retained copy result"),
            }
        }
    }

    fn start(&mut self, from: u64, to: Option<u64>) {
        self.count = self.count.min(Vfs::MAX_RW_COUNT);
        self.stage = Some(CopyStage {
            from,
            to,
            bytes: None,
            written: None,
            source_committed: false,
            output_committed: false,
            offered: 0,
        });
    }

    fn drive(&mut self, v: &mut Vfs, input: u32, output: u32) -> Result<FileValue> {
        if self.source_position.is_none() && self.from?.is_none() {
            let descriptor = v.descriptor(input)?;
            let source = SharedFd::new(descriptor.open.borrow().shared.clone());
            if source.open.is_regular_file() {
                self.source_position = Some(transfer_io::Position::capture(
                    source,
                    Some(self.stage.as_ref().unwrap().from),
                ));
            }
        }
        if self.output_position.is_none() && self.to?.is_none() {
            let target = SharedFd::new(v.descriptor(output)?.open.borrow().shared.clone());
            if target.open.is_regular_file() {
                let position = transfer_io::Position::capture(
                    target,
                    self.stage.as_ref().unwrap().to.or(self.start_to),
                );
                self.start_to = Some(position.offset);
                self.output_position = Some(position);
            }
        }
        loop {
            let chunk = self.chunk_size();
            let stage = self.stage.as_mut().unwrap();
            let (from, to) = (stage.from, stage.to);
            if stage.bytes.is_none() {
                let read = self
                    .io
                    .call(
                        &v.descriptor(input)?,
                        v,
                        FileCommand::Read {
                            count: chunk,
                            offset: Some(from),
                        },
                        transfer_io::Step::Read,
                    )
                    .and_then(transfer_io::Io::bytes);
                match read {
                    Ok(bytes) if self.copied > 0 && bytes.is_empty() => {
                        return Ok(self.result(from, to))
                    }
                    Ok(bytes) => {
                        stage.offered = bytes.len();
                        stage.bytes = Some(bytes);
                    }
                    Err(e)
                        if self.copied == 0 || v.query.as_ref().is_some_and(|q| q.deferred()) =>
                    {
                        return Err(e)
                    }
                    Err(_) => return Ok(self.result(from, to)),
                }
            }
            let out = v.descriptor(output)?;
            let result = if let Some((written, original_offered)) = stage.written {
                stage.offered = original_offered;
                Ok(written)
            } else if transfer_io::Io::regular(&SharedFd::new(out.open.borrow().shared.clone())) {
                let bytes = stage.bytes.as_mut().unwrap();
                let tail = if to.is_none()
                    && !self.io.retained()
                    && !bytes.is_empty()
                    && bytes.len() < chunk
                {
                    v.descriptor(input)?
                        .open
                        .borrow()
                        .data_node()
                        .zip(out.open.borrow().node.clone())
                        .is_some_and(|(source, target)| {
                            source.regular_file && Arc::ptr_eq(&source, &target)
                        })
                        .then_some((from, chunk))
                } else {
                    None
                };
                // An implicit destination belongs to its original OFD. The
                // retained child acquires that position before writing bytes.
                let at = to;
                let result = self.io.write(&out, v, bytes, at, tail);
                stage.offered = self.io.offered();
                result
            } else if let Some(to) = to {
                v.pwrite(output, stage.bytes.as_ref().unwrap(), to)
            } else {
                v.write(output, stage.bytes.as_ref().unwrap())
            };
            let written = match result {
                Ok(n) => n,
                Err(Errno(11))
                    if !self.io.retained()
                        && v.descriptor(output)?
                            .open
                            .borrow()
                            .file_position
                            .lock()
                            .unwrap()
                            .pending
                            != 0 =>
                {
                    return self.io.wait_position(
                        v,
                        v.descriptor(output)?.open.borrow().file_position.clone(),
                    );
                }
                // A deferred layout keeps this stage and the cumulative count.
                // The outer file transaction retries it before publishing a reply.
                Err(e) if self.copied == 0 || v.query.as_ref().is_some_and(|q| q.deferred()) => {
                    return Err(e)
                }
                Err(_) => return Ok(self.result(from, to)),
            };
            let short = written < stage.offered;
            stage.written = Some((written, stage.offered));
            let written = written as u64;
            let from = from + written;
            let to = to.map(|p| p + written);
            if self.from?.is_none() && !stage.source_committed {
                if let Some(position) = &self.source_position {
                    if written != 0 && !position.try_record(from) {
                        return self.io.wait_position(v, position.position());
                    }
                } else {
                    self.io.seek(v, &v.descriptor(input)?, from as i64, 0)?;
                }
                stage.source_committed = true;
            }
            if self.to?.is_none() && !stage.output_committed {
                if let Some(position) = &self.output_position {
                    if written != 0 {
                        position.record(
                            self.io
                                .write_end()
                                .unwrap_or(position.offset + self.copied + written),
                        );
                    }
                } else if let Some(to) = to {
                    self.io.seek(v, &v.descriptor(output)?, to as i64, 0)?;
                }
                stage.output_committed = true;
            }
            self.copied += written;
            if short || written == 0 || self.copied == self.count {
                return Ok(self.result(from, to));
            }
            self.stage = Some(CopyStage {
                from,
                to,
                bytes: None,
                written: None,
                source_committed: false,
                output_committed: false,
                offered: 0,
            });
        }
    }

    fn chunk_size(&self) -> usize {
        (self.count - self.copied).min(storage::MAX_TRANSFER as u64) as usize
    }

    fn result(&self, from: u64, to: Option<u64>) -> FileValue {
        FileValue::Transfer {
            count: self.copied,
            from,
            to,
        }
    }
}
impl Vfs {
    pub(super) fn transfer_work(&mut self, work: FileWork) -> Result<FileValue> {
        if self.query.is_none() {
            return host_sync::Wait::default().file(self, work.run());
        }
        match work.run() {
            FileOutcome::Complete(reply) => reply.result,
            FileOutcome::Waiting(work) | FileOutcome::Layout(work) | FileOutcome::Owner(work) => {
                let query = self.query.as_ref().ok_or(Errno(95))?;
                query.prepared.borrow_mut().work = Some(std::sync::Mutex::new(work));
                query.defer()
            }
        }
    }
    fn with_file_peer<T>(
        &mut self,
        input: &FileTarget,
        operation: impl FnOnce(&mut Vfs, u32) -> T,
    ) -> T {
        struct Restore<'a> {
            v: &'a mut Vfs,
            old: Option<Descriptor>,
            peer: Option<(u32, SharedFd)>,
        }
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                self.v.fds.remove(&MAX_FDS);
                if let Some(old) = self.old.take() {
                    self.v.fds.insert(MAX_FDS, old);
                }
                if let Some(q) = &mut self.v.query {
                    q.peer = self.peer.take();
                }
            }
        }
        let old = self.fds.insert(
            MAX_FDS,
            Descriptor {
                open: OpenHandle::Shared(input.0.open.clone()),
                cloexec: false.into(),
            },
        );
        let peer = self
            .query
            .as_mut()
            .and_then(|q| q.peer.replace((MAX_FDS, input.0.clone())));
        let guard = Restore { v: self, old, peer };
        operation(guard.v, MAX_FDS)
    }
}
