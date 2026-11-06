// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted filesystem operations. Host work owns original OFDs and owned bytes;
//! guest pointers, source task execution and descriptor membership stay outside.
use super::*;

#[derive(Clone)]
pub struct FileTarget(pub(super) SharedFd);
impl FileTarget {
    fn proc_read(&self, command: &FileCommand) -> Option<proc_file::ProcRead> {
        let FileCommand::Read { count, offset } = command else {
            return None;
        };
        let open = &self.0.open;
        let file = open.runtime_file.as_ref()?;
        if !file.live_payload() {
            return None;
        }
        if open.flags.get() & O_PATH != 0 || open.flags.get() & 3 == 1 {
            return Some(proc_file::ProcRead::Complete(Err(Errno(9))));
        }
        if let Some(offset) = offset {
            return Some(if *offset > i64::MAX as u64 {
                proc_file::ProcRead::Complete(Err(Errno(22)))
            } else {
                file.read_payload(*offset, *count)
            });
        }
        let mut position = open.file_position.lock().unwrap();
        let result = file.read_payload(position.value, *count);
        if let proc_file::ProcRead::Complete(Ok(bytes)) = &result {
            position.value += bytes.len() as u64;
        }
        Some(result)
    }
    fn waits(&self, command: &FileCommand) -> bool {
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
        if !file.live_payload() {
            return None;
        }
        if open.flags.get() & O_PATH != 0 || open.flags.get() & 3 == 1 {
            return Some(Err(Errno(9)));
        }
        if let Some(offset) = offset {
            if *offset > i64::MAX as u64 {
                return Some(Err(Errno(22)));
            }
            return file
                .read_local(*offset, *count, memory)
                .map(|r| r.map(FileValue::Bytes));
        }
        let mut position = open.file_position.lock().unwrap();
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
            FileCommand::Read { .. } => persistent,
            FileCommand::Write { .. } | FileCommand::WriteSync { .. } => persistent,
            FileCommand::Sync { .. } | FileCommand::SyncFilesystem | FileCommand::SyncAll => {
                persistent || data.mapped_work()
            }
            FileCommand::Truncate(_) | FileCommand::Allocate { .. } => {
                persistent || data.mapped_work()
            }
        }
    }
}
impl SharedFd {
    pub fn filesystem_target(&self) -> FileTarget {
        FileTarget(self.clone())
    }
    pub fn file_target(&self) -> Option<FileTarget> {
        let open = &self.open;
        if open.control.is_some()
            || !open.proc_control() && !open.node.as_ref().is_some_and(|node| node.regular_file)
        {
            return None;
        }
        Some(FileTarget(self.clone()))
    }
}

pub enum FileCommand {
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
    Allocate {
        mode: u64,
        offset: u64,
        length: u64,
    },
    Sync {
        data_only: bool,
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
    /// A genuine mapping-layout boundary, with original input retained. There
    /// have been no output effects; a copy retains its accepted input bytes.
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
    proc_wait: Vec<trames_memory::MemoryRead>,
}
struct FileActive(Arc<Inode>);
impl Drop for FileActive {
    fn drop(&mut self) {
        self.0.active_file_work.fetch_sub(1, Ordering::Relaxed);
    }
}
pub(super) struct PreparedOpen {
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
    pub fn waiting(&self) -> bool {
        self.namespace.as_ref().is_some_and(|work| work.waiting())
            || !self.proc_wait.is_empty()
            || matches!(&self.command, FileCommand::Transfer(t) if t.borrow().waits())
    }
    pub fn ready(&self) -> bool {
        if let Some(work) = &self.namespace {
            return work.ready();
        }
        match &self.command {
            FileCommand::Transfer(t) => t.borrow().ready(),
            _ => self.proc_wait.iter().all(|page| page.ready()),
        }
    }
    pub fn wait_sources(&self, signal: &Arc<IoSignal>) -> std::io::Result<TransferWait> {
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
        match &self.command {
            FileCommand::Transfer(t) => t.borrow().native_wait_fds(),
            _ => Vec::new(),
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
        }
    }
    pub fn host_work(&self) -> bool {
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
        }
    }
    pub fn queued(mut self) -> Self {
        if self.namespace.is_none()
            && self.sync_targets.is_none()
            && matches!(
                self.command,
                FileCommand::SyncAll | FileCommand::SyncFilesystem
            )
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
    pub fn run(mut self) -> FileOutcome {
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
                if result.as_ref().is_err_and(|e| e.0 == 11) && self.waiting() {
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
        struct Capture<'a>(&'a mut Vfs);
        impl Drop for Capture<'_> {
            fn drop(&mut self) {
                self.0.query.as_mut().unwrap().capture_open = false;
            }
        }
        let mut view = self.view.borrow_mut();
        let query = view.query.as_mut().unwrap();
        query.capture_open = true;
        query.clear_deferred();
        let guard = Capture(&mut view);
        let result = guard
            .0
            .open_at_resolve_published(AT_FDCWD, path, 1, 0, 0, None);
        drop(guard);
        let query = view.query.as_ref().unwrap();
        let accepted = query.open_work.borrow_mut().take();
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
    pub fn take_open_work(&self) -> Option<FileWork> {
        let open = self
            .view
            .borrow()
            .query
            .as_ref()?
            .open_work
            .borrow_mut()
            .take()?;
        let mut work = FileWork::new(self, open.target.clone(), FileCommand::Truncate(0));
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
        let descriptor = Descriptor {
            open: OpenHandle::Shared(target.0.open.clone()),
            cloexec: false.into(),
        };
        match self {
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
                if *offset > i64::MAX as u64 {
                    return Err(Errno(22));
                }
                v.pread_description(&descriptor, *count, *offset)
                    .map(FileValue::Bytes)
            }
            Self::Write { bytes, offset } | Self::WriteSync { bytes, offset, .. } => {
                if offset.is_some_and(|offset| offset > i64::MAX as u64) {
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
    stage: Option<(u64, Option<u64>, Vec<u8>)>,
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
        }
    }
    fn execute(&mut self, v: &mut Vfs, input: u32, output: u32) -> Result<FileValue> {
        if self.stage.is_none() {
            if !self.range && v.flags(output)? & 0x400 != 0 {
                return Err(Errno(22));
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
                if source[..16] == target[..16]
                    && from < offset.saturating_add(self.count)
                    && offset < from.saturating_add(self.count)
                {
                    return Err(Errno(22));
                }
                Some(offset)
            } else {
                None
            };
            let bytes = v.pread(
                input,
                self.count.min(storage::MAX_TRANSFER as u64) as usize,
                from,
            )?;
            self.stage = Some((from, to, bytes));
        }
        let (from, to, bytes) = self.stage.as_ref().unwrap();
        let written = if let Some(to) = to {
            v.pwrite(output, bytes, *to)?
        } else {
            v.write(output, bytes)?
        } as u64;
        if self.from?.is_none() {
            v.seek(input, (from + written) as i64, 0)?;
        }
        if let Some(to) = to {
            if self.to?.is_none() {
                v.seek(output, (to + written) as i64, 0)?;
            }
        }
        Ok(FileValue::Transfer {
            count: written,
            from: from + written,
            to: to.map(|to| to + written),
        })
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
