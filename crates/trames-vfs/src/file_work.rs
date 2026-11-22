// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted filesystem operations. Host work owns original OFDs and owned bytes;
//! guest pointers, source task execution and descriptor membership stay outside.
use super::*;
use std::sync::atomic::AtomicUsize;

#[derive(Clone)]
pub struct FileTarget(pub(super) SharedFd);
impl FileTarget {
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
    fn proc_position_command(&self, command: &FileCommand) -> bool {
        matches!(
            command,
            FileCommand::Read { offset: None, .. }
                | FileCommand::Write { offset: None, .. }
                | FileCommand::WriteSync { offset: None, .. }
                | FileCommand::Seek { .. }
        ) && self
            .0
            .open
            .runtime_file
            .as_ref()
            .is_some_and(|f| f.is_memory())
    }
    fn proc_position_busy(&self, command: &FileCommand) -> bool {
        self.proc_position_command(command)
            && self.0.open.file_position.lock().unwrap().pending != 0
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

    fn proc_read(&self, command: &FileCommand) -> Option<proc_file::ProcRead> {
        let FileCommand::Read { count, offset } = command else {
            return None;
        };
        let open = &self.0.open;
        let file = open.runtime_file.as_ref()?;
        if !file.live_payload() {
            return None;
        }
        if !fd_can_read(open.flags.get()) {
            return Some(proc_file::ProcRead::Complete(Err(Errno(9))));
        }
        if let Some(offset) = offset {
            return Some(if *offset > i64::MAX as u64 && !file.is_memory() {
                proc_file::ProcRead::Complete(Err(Errno(22)))
            } else {
                file.read_payload(*offset, *count)
            });
        }
        let mut position = open.file_position.lock().unwrap();
        if position.pending != 0 {
            return Some(proc_file::ProcRead::Waiting(Vec::new()));
        }
        let result = file.read_payload(position.value, *count);
        if let proc_file::ProcRead::Complete(Ok(bytes)) = &result {
            position.value += bytes.len() as u64;
        }
        Some(result)
    }
    fn waits(&self, command: &FileCommand) -> bool {
        if self.proc_position_command(command) {
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
        matches!(command, FileCommand::Transfer(t) if t.borrow().waits())
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
        let mut position = open.file_position.lock().unwrap();
        if position.pending != 0 {
            return None;
        }
        file.read_local(position.value, *count, memory).map(|r| {
            r.map(|bytes| {
                position.value += bytes.len() as u64;
                FileValue::Bytes(bytes)
            })
        })
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
            FileCommand::Transfer(transfer) => transfer.borrow().host_work_owned(),
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
            return transfer.borrow().host_work();
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
            FileCommand::Transfer(transfer) => transfer.borrow().host_work(),
            FileCommand::Seek { .. } => persistent,
            FileCommand::Stat => false,
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
        if matches!(open.control, Some(events::SharedControl::FuseFile(_))) {
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

pub enum FileCommand {
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
    Transfer(RefCell<StreamTransfer>),
    Copy {
        input: FileTarget,
        transfer: RefCell<FileCopy>,
    },
}
pub enum FileValue {
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
    pub file_size_signal: bool,
    pub scratch: Option<Vec<u8>>,
}
pub enum FileOutcome {
    Complete(FileReply),
    /// No bytes committed: the source task parks on the accepted endpoint.
    Waiting(FileWork),
    /// A mapping-layout boundary. A copy retains its committed prefix, current
    /// offsets and accepted input for the chunk awaiting the layout change.
    Layout(FileWork),
    /// A namespace call met an original owner-only task/proc/mount resource,
    /// before effects. Its copied operands and accepted shared FDs survive.
    Owner(FileWork),
}
pub struct FileWork {
    paths: Box<PathQueries>,
    target: Option<FileTarget>,
    command: FileCommand,
    exclusive: bool,
    layout_exclusive: Option<trames_memory::layout::LayoutExclusive>,
    active: Option<FileActive>,
    input_active: Option<FileActive>,
    open: Option<Box<PreparedOpen>>,
    sync_targets: Option<Vec<storage::FilesystemSync>>,
    namespace: Option<Box<namespace_work::NamespaceWork>>,
    proc_wait: Vec<proc_file::ProcWait>,
    proc_memory: Option<Box<ProcMemory>>,
    fuse_stat: Option<Box<fuse::Metadata>>,
    linger: Option<Box<trames_net::TcpLinger>>,
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
            FileValue::Bytes(std::mem::take(&mut self.output))
        }
    }
}
struct ProcPosition {
    position: Arc<file_data::FilePosition>,
    offset: u64,
    committed: AtomicUsize,
}
impl ProcPosition {
    fn record(&self, count: usize) {
        self.committed.store(count, Ordering::Relaxed);
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
    /// Cold non-data descriptors use their canonical ABI body rather than the
    /// regular-file write specialization. No byte provider or host job is added.
    pub fn descriptor_reply(
        paths: &PathQueries,
        target: FileTarget,
        mut command: FileCommand,
    ) -> FileReply {
        let result = paths.retained_control(target.0, |vfs, fd| command.execute(vfs, fd));
        Self::descriptor_result(result, &mut command)
    }
    pub fn descriptor_owned(
        vfs: &mut Vfs,
        target: FileTarget,
        mut command: FileCommand,
    ) -> FileReply {
        let result = vfs.with_uring_fd(&target.0.retained(), |vfs, fd| command.execute(vfs, fd));
        Self::descriptor_result(result, &mut command)
    }
    fn descriptor_result(result: Result<FileValue>, command: &mut FileCommand) -> FileReply {
        let scratch = match command {
            FileCommand::Write { bytes, .. } | FileCommand::WriteSync { bytes, .. } => {
                Some(std::mem::take(bytes))
            }
            _ => None,
        };
        FileReply {
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
        self.fuse_request().is_some()
    }
    pub fn fuse_interrupt_needed(&self) -> bool {
        self.fuse_request().is_some_and(|p| p.needs_interrupt())
    }
    pub fn fuse_signal_request(&self) -> Option<Arc<fuse::Request>> {
        self.fuse_request().map(|p| p.request.clone())
    }
    fn position_wait(&self) -> Option<&fuse::File> {
        if !matches!(
            self.command,
            FileCommand::Read { offset: None, .. } | FileCommand::Write { offset: None, .. }
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
        if self.proc_memory.is_some()
            || self
                .target
                .as_ref()
                .is_some_and(|t| t.proc_position_busy(&self.command))
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
            return file.busy();
        }
        if self.console_wait().is_some() {
            return !self.ready();
        }
        self.namespace.as_ref().is_some_and(|work| work.waiting())
            || !self.proc_wait.is_empty()
            || matches!(&self.command, FileCommand::Transfer(t) if t.borrow().waits())
    }
    pub fn ready(&self) -> bool {
        if let Some(io) = &self.proc_memory {
            return io.request.as_ref().is_none_or(|r| r.ready());
        }
        if self
            .target
            .as_ref()
            .is_some_and(|t| t.proc_position_busy(&self.command))
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
            return !file.busy();
        }
        if let Some((console, writing)) = self.console_wait() {
            return console
                .io
                .poll(console.stream, if writing { 4 } else { 1 })
                .0
                != 0;
        }
        if let Some(work) = &self.namespace {
            return work.ready();
        }
        match &self.command {
            FileCommand::Transfer(t) => t.borrow().ready(),
            _ => self.proc_wait.iter().all(|page| page.ready()),
        }
    }
    pub fn wait_sources(&self, signal: &Arc<IoSignal>) -> std::io::Result<TransferWait> {
        if let Some(request) = self.proc_memory.as_ref().and_then(|io| io.request.as_ref()) {
            return Ok(TransferWait {
                subscriptions: vec![request.subscribe(signal)],
                native: Vec::new(),
                deadline: None,
            });
        }
        if let Some(target) = self
            .target
            .as_ref()
            .filter(|t| t.proc_position_busy(&self.command))
        {
            return Ok(TransferWait {
                subscriptions: vec![target.0.open.file_position.subscribe_pending(signal)],
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
                subscriptions: vec![p.subscribe(signal)],
                native: vec![],
                deadline: None,
            });
        }
        if let Some(file) = self.position_wait() {
            return Ok(TransferWait {
                subscriptions: vec![file.subscribe_position(signal)],
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
        if let Some(work) = &self.namespace {
            return Ok(TransferWait {
                subscriptions: work.subscribe(signal).into_iter().collect(),
                native: Vec::new(),
                deadline: None,
            });
        }
        match &self.command {
            FileCommand::Transfer(t) => t.borrow().wait_sources(signal),
            _ => Ok(TransferWait {
                subscriptions: self.proc_wait.iter().map(|p| p.subscribe(signal)).collect(),
                native: Vec::new(),
                deadline: None,
            }),
        }
    }
    fn proc_outcome(result: proc_file::ProcRead, work: impl FnOnce() -> Self) -> FileOutcome {
        match result {
            proc_file::ProcRead::Complete(result) => FileOutcome::Complete(FileReply {
                result: result.map(FileValue::Bytes),
                file_size_signal: false,
                scratch: None,
            }),
            proc_file::ProcRead::Waiting(pages) => {
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
            FileCommand::Transfer(t) => t.borrow().native_wait_fds(),
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
            namespace: Some(Box::new(namespace)),
            ..Self::sync_all(paths)
        }
    }
    pub fn run_owner(self, vfs: &mut Vfs) -> FileReply {
        let result = self
            .namespace
            .as_ref()
            .expect("retained namespace owner call")
            .run_owner(&self.paths, vfs);
        FileReply {
            result,
            file_size_signal: false,
            scratch: None,
        }
    }
    pub fn sync_all(paths: PathQueries) -> Self {
        Self {
            paths: Box::new(paths),
            target: None,
            command: FileCommand::SyncAll,
            exclusive: false,
            layout_exclusive: None,
            active: None,
            input_active: None,
            open: None,
            sync_targets: None,
            namespace: None,
            proc_wait: Vec::new(),
            proc_memory: None,
            fuse_stat: None,
            linger: None,
        }
    }
    pub fn host_work(&self) -> bool {
        if self.target.as_ref().is_some_and(|t| {
            t.proc_memory_command(&self.command) || t.proc_position_busy(&self.command)
        }) {
            return false;
        }

        if self.fuse_stat.is_some() || self.linger.is_some() {
            return false;
        }
        if let Some(namespace) = &self.namespace {
            return namespace.host_work();
        }
        self.target
            .as_ref()
            .is_none_or(|target| target.host_work(&self.command))
    }
    pub fn new(paths: &PathQueries, target: FileTarget, command: FileCommand) -> Self {
        Self {
            paths: Box::new(paths.file_context(&target)),
            target: Some(target),
            command,
            exclusive: false,
            layout_exclusive: None,
            active: None,
            input_active: None,
            open: None,
            sync_targets: None,
            namespace: None,
            proc_wait: Vec::new(),
            proc_memory: None,
            fuse_stat: None,
            linger: None,
        }
    }
    pub fn from_vfs(vfs: &Vfs, target: FileTarget, command: FileCommand) -> Self {
        Self {
            paths: Box::new(PathQueries::file_view(vfs, &target)),
            target: Some(target),
            command,
            exclusive: false,
            layout_exclusive: None,
            active: None,
            input_active: None,
            open: None,
            sync_targets: None,
            namespace: None,
            proc_wait: Vec::new(),
            proc_memory: None,
            fuse_stat: None,
            linger: None,
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
            self.sync_targets = Some(
                self.paths
                    .view
                    .borrow()
                    .sync_targets(matches!(self.command, FileCommand::SyncAll))
                    .into_iter()
                    .map(storage::FilesystemSync::queued)
                    .collect(),
            );
        }
        if self.input_active.is_none() {
            let input = match &self.command {
                FileCommand::Copy { input, .. } => Some(input.clone()),
                FileCommand::Transfer(t) => t.borrow().input.file_target(),
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
    pub fn run_owned(vfs: &mut Vfs, target: FileTarget, mut command: FileCommand) -> FileOutcome {
        if target.proc_memory_command(&command) || target.proc_position_busy(&command) {
            return Self::from_vfs(vfs, target, command).run();
        }

        if let Some(result) = target.proc_read(&command) {
            return Self::proc_outcome(result, || Self::from_vfs(vfs, target, command));
        }
        let result = command.execute_target(vfs, &target);
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
            result,
            file_size_signal: signal,
            scratch,
        })
    }
    pub fn run_inline(
        paths: &PathQueries,
        target: FileTarget,
        mut command: FileCommand,
    ) -> FileOutcome {
        if target.proc_memory_command(&command) || target.proc_position_busy(&command) {
            return Self::new(paths, target, command).run();
        }
        if matches!(
            target.0.open.control,
            Some(events::SharedControl::FuseFile(_))
        ) {
            return Self::new(paths, target, command).run();
        }
        if let Some(result) = target.proc_read(&command) {
            return Self::proc_outcome(result, || Self::new(paths, target, command));
        }
        match paths.file_command(&target, &command, false) {
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
                    result,
                    file_size_signal: signal,
                    scratch,
                })
            }
            None => FileOutcome::Layout(Self::new(paths, target, command)),
        }
    }
    pub fn layout_domains(&self) -> Vec<u64> {
        self.target
            .as_ref()
            .map_or_else(Vec::new, FileTarget::layout_domains)
    }
    pub fn target(&self) -> Option<&FileTarget> {
        self.target.as_ref()
    }
    pub fn exclusive(mut self) -> Self {
        self.exclusive = true;
        self
    }
    pub fn begin_layout(&self) -> Option<trames_memory::layout::LayoutWrite> {
        self.target.as_ref()?.layout().map(|layout| layout.write())
    }
    pub fn enter_layout(mut self, exclusive: trames_memory::layout::LayoutExclusive) -> Self {
        let original = self
            .target
            .as_ref()
            .and_then(FileTarget::layout)
            .expect("mapped original inode");
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
                if let Some(position) = &io.position {
                    position.record(io.done);
                }
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
    pub fn run(mut self) -> FileOutcome {
        if let Some(result) = self.proc_memory_step() {
            return match result {
                Ok(None) => FileOutcome::Waiting(self),
                result => FileOutcome::Complete(FileReply {
                    result: result.map(Option::unwrap),
                    file_size_signal: false,
                    scratch: None,
                }),
            };
        }
        if self
            .target
            .as_ref()
            .is_some_and(|t| t.proc_position_busy(&self.command))
        {
            return FileOutcome::Waiting(self);
        }

        if let Some(wait) = &self.linger {
            return if wait.ready() {
                FileOutcome::Complete(FileReply {
                    result: Ok(FileValue::Count(0)),
                    file_size_signal: false,
                    scratch: None,
                })
            } else {
                FileOutcome::Waiting(self)
            };
        }
        if let Some(p) = &mut self.fuse_stat {
            return match p.take() {
                Some(result) => FileOutcome::Complete(FileReply {
                    result,
                    file_size_signal: false,
                    scratch: None,
                }),
                None => FileOutcome::Waiting(self),
            };
        }
        if let Some(target) = &self.target {
            if let Some(events::SharedControl::FuseFile(file)) = &target.0.open.control {
                let pending = file.operation(
                    &self.paths.view.borrow(),
                    &self.command,
                    &target.0.open.file_position,
                );
                return match pending {
                    Ok(op) => {
                        self.fuse_stat = op.map(Box::new);
                        FileOutcome::Waiting(self)
                    }
                    Err(error) => FileOutcome::Complete(FileReply {
                        result: Err(error),
                        file_size_signal: false,
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
                        result,
                        file_size_signal: false,
                        scratch: None,
                    })
                }
                namespace_work::NamespaceRun::Owner => FileOutcome::Owner(self),
                namespace_work::NamespaceRun::Waiting => FileOutcome::Waiting(self),
            };
        }
        let reply = if let Some(targets) = &self.sync_targets {
            Some((
                targets
                    .iter()
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
        match reply {
            Some((mut result, signal)) => {
                if result.as_ref().is_err_and(|e| e.0 == 11)
                    && (self.console_wait().is_some() || self.waiting())
                {
                    return FileOutcome::Waiting(self);
                }
                if result.is_ok() {
                    if let Some(open) = self.open.take() {
                        result = open
                            .publish(&self.paths)
                            .map(|fd| FileValue::Count(fd as u64));
                    }
                }
                let scratch = match &mut self.command {
                    FileCommand::Write { bytes, .. } | FileCommand::WriteSync { bytes, .. } => {
                        Some(std::mem::take(bytes))
                    }
                    _ => None,
                };
                FileOutcome::Complete(FileReply {
                    result,
                    file_size_signal: signal,
                    scratch,
                })
            }
            None => FileOutcome::Layout(self),
        }
    }
}
impl PathQueries {
    pub fn truncate_path_work(&self, path: &[u8], length: u64) -> Option<Result<FileWork>> {
        let mut view = self.view.borrow_mut();
        view.query.as_ref().unwrap().clear_deferred();
        let result = view.open_at_resolve_published::<true>(AT_FDCWD, path, 1, 0, 0, None);
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
    fn file_context(&self, target: &FileTarget) -> Self {
        let original = self.view.borrow();
        Self::file_view(&original, target)
    }
    fn file_view(original: &Vfs, target: &FileTarget) -> Self {
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
        if matches!(open.control, Some(events::SharedControl::FuseFile(_))) {
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
        let mut view = self.view.borrow_mut();
        let authority = view.query.as_mut().expect("sealed file authority");
        authority.file_layout_exclusive = exclusive;
        authority.clear_deferred();
        view.file_size_signal.set(false);
        let result = command.execute_target(&mut view, target);
        let signal = view.file_size_signal.replace(false);
        let authority = view.query.as_ref().unwrap();
        (!authority.take_deferred()).then_some((result, signal))
    }
}

impl FileCommand {
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
            Self::Transfer(transfer) => transfer.borrow_mut().execute(v),
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
                let count = v.file_write_description(&descriptor, bytes, *offset)?;
                if let Self::WriteSync { data_only, .. } = self {
                    v.sync_description(&descriptor, *data_only)?;
                }
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
            FileCommand::Transfer(transfer) => transfer.borrow_mut().execute(v),
            FileCommand::Copy { input, transfer } => v.with_file_peer(input, |v, input| {
                transfer.borrow_mut().execute(v, input, fd)
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
}
struct CopyStage {
    from: u64,
    to: Option<u64>,
    bytes: Option<Vec<u8>>,
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
        }
    }
    fn execute(&mut self, v: &mut Vfs, input: u32, output: u32) -> Result<FileValue> {
        if self.stage.is_none() {
            if !self.range {
                Vfs::check_sendfile_modes(v.flags(input)?, v.flags(output)?)?;
            }
            let source = v.stat_fd(input)?;
            v.fd_kind(output)?;
            let from = match self.from? {
                Some(offset) => offset,
                None => v.seek(input, 0, 1)?,
            };
            let to = if self.range {
                let target = v.stat_fd(output)?;
                if v.flags(output)? & 0x400 != 0 {
                    return Err(Errno(9));
                }
                let offset = match self.to? {
                    Some(offset) => offset,
                    None => v.seek(output, 0, 1)?,
                };
                self.count =
                    Vfs::copy_file_range_length(&source, &target, from, offset, self.count)?;
                Some(offset)
            } else {
                None
            };
            if !self.range {
                Vfs::check_io_range(from, self.count)?;
                if v.regular_file_fd(output)? {
                    Vfs::check_io_range(v.seek(output, 0, 1)?, self.count.min(Vfs::MAX_RW_COUNT))?;
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
        self.drive(v, input, output)?;
        Ok(self.copied)
    }

    fn start(&mut self, from: u64, to: Option<u64>) {
        self.count = self.count.min(Vfs::MAX_RW_COUNT);
        self.stage = Some(CopyStage {
            from,
            to,
            bytes: None,
        });
    }

    fn drive(&mut self, v: &mut Vfs, input: u32, output: u32) -> Result<FileValue> {
        loop {
            let chunk = self.chunk_size();
            let stage = self.stage.as_mut().unwrap();
            let (from, to) = (stage.from, stage.to);
            if stage.bytes.is_none() {
                match v.pread(input, chunk, from) {
                    Ok(bytes) if self.copied > 0 && bytes.is_empty() => {
                        return Ok(self.result(from, to))
                    }
                    Ok(bytes) => stage.bytes = Some(bytes),
                    Err(e) if self.copied == 0 => return Err(e),
                    Err(_) => return Ok(self.result(from, to)),
                }
            }
            let bytes = stage.bytes.as_ref().unwrap();
            let mut offered = bytes.len();
            let result = if let Some(to) = to {
                v.pwrite(output, bytes, to)
            } else if !bytes.is_empty() && bytes.len() < chunk {
                let out = v.descriptor(output)?;
                let source = v.descriptor(input)?.open.borrow().data_node();
                let same = source
                    .zip(out.open.borrow().node.clone())
                    .is_some_and(|(s, d)| s.regular_file && Arc::ptr_eq(&s, &d));
                if same {
                    v.file_write_description_inner::<true>(
                        &out,
                        bytes,
                        None,
                        (from, chunk),
                        &mut offered,
                    )
                } else {
                    v.write_description(&out, bytes)
                }
            } else {
                v.write(output, bytes)
            };
            let written = match result {
                Ok(n) => n,
                // A deferred layout keeps this stage and the cumulative count.
                // The outer file transaction retries it before publishing a reply.
                Err(e) if self.copied == 0 => return Err(e),
                Err(_) => return Ok(self.result(from, to)),
            };
            let short = written < offered;
            let written = written as u64;
            let from = from + written;
            let to = to.map(|p| p + written);
            self.copied += written;
            if self.from?.is_none() {
                v.seek(input, from as i64, 0)?;
            }
            if let Some(to) = to {
                if self.to?.is_none() {
                    v.seek(output, to as i64, 0)?;
                }
            }
            if short || written == 0 || self.copied == self.count {
                return Ok(self.result(from, to));
            }
            self.stage = Some(CopyStage {
                from,
                to,
                bytes: None,
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
