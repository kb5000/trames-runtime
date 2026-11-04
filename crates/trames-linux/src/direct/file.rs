// SPDX-License-Identifier: GPL-3.0-or-later
//! Source-worker file calls and direct completion from the existing disk pool.
use super::*;
use std::sync::Mutex;

pub trait FileExecutor: Send + Sync {
    fn submit_file(&self, job: trames_vfs::FileWork, result: Arc<FileResult>);
}
pub struct FileResult {
    result: Mutex<Option<trames_vfs::FileOutcome>>,
    readiness: Arc<trames_vfs::Readiness>,
    owner: std::sync::OnceLock<std::thread::Thread>,
    finished: std::sync::atomic::AtomicBool,
}
impl Default for FileResult {
    fn default() -> Self {
        Self {
            result: Mutex::new(None),
            readiness: Arc::default(),
            owner: Default::default(),
            finished: Default::default(),
        }
    }
}
impl FileResult {
    pub fn wake_joined() -> Self {
        Self {
            owner: std::sync::OnceLock::from(std::thread::current()),
            ..Default::default()
        }
    }
    pub fn complete(&self, result: trames_vfs::FileOutcome) {
        *self.result.lock().unwrap() = Some(result);
        self.finished
            .store(true, std::sync::atomic::Ordering::Release);
        self.readiness.notify_locked();
        if let Some(owner) = self.owner.get() {
            owner.unpark();
        }
    }
    pub fn fail(&self, errno: u32) {
        self.complete(trames_vfs::FileOutcome::Complete(trames_vfs::FileReply {
            result: Err(Errno(errno)),
            file_size_signal: false,
            scratch: None,
        }));
    }
    pub fn begin(&self) {
        self.finished
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn finished(&self) -> bool {
        self.finished.load(std::sync::atomic::Ordering::Acquire)
    }
    pub fn wake_owner(&self) {
        let _ = self.owner.set(std::thread::current());
    }
    pub fn ready(&self) -> bool {
        self.result.lock().unwrap().is_some()
    }
    pub(super) fn take(&self) -> Option<trames_vfs::FileOutcome> {
        self.result.lock().unwrap().take()
    }
    pub(super) fn subscribe(&self, signal: &Arc<IoSignal>) -> trames_vfs::IoSubscription {
        self.readiness.subscribe(signal)
    }
}

#[derive(Clone)]
pub enum FileOutput {
    None,
    Scalar(u64),
    Vectors(Vec<(u64, usize)>),
    Stat(u64),
    Buffer {
        address: u64,
        capacity: u64,
        query_size: bool,
        zero: bool,
    },
    CopyOffsets {
        from: u64,
        to: u64,
    },
}
impl FileOutput {
    pub fn apply(
        &self,
        result: Result<trames_vfs::FileValue, Errno>,
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        match result? {
            trames_vfs::FileValue::Transfer { count, from, to } => {
                let Self::CopyOffsets {
                    from: input,
                    to: output,
                } = self
                else {
                    unreachable!("accepted copy output")
                };
                if *input != 0 {
                    memory
                        .write(*input, &from.to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                if let Some(to) = to.filter(|_| *output != 0) {
                    memory
                        .write(*output, &to.to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                Ok(count)
            }
            trames_vfs::FileValue::Count(count) => Ok(count),
            trames_vfs::FileValue::Bytes(bytes) => {
                match self {
                    Self::Scalar(address) => {
                        memory.write(*address, &bytes).map_err(|_| Errno(14))?
                    }
                    Self::Vectors(parts) => Linux::scatter(memory, parts, &bytes)?,
                    Self::Buffer {
                        address,
                        capacity,
                        query_size,
                        zero,
                    } => {
                        if !(*query_size && *capacity == 0) {
                            if *capacity < bytes.len() as u64 {
                                return Err(Errno(34));
                            }
                            Linux::check(memory, *address, bytes.len(), Access::Write)?;
                            memory.write(*address, &bytes).map_err(|_| Errno(14))?;
                        }
                        return Ok(if *zero { 0 } else { bytes.len() as u64 });
                    }
                    _ => unreachable!("accepted read output"),
                }
                Ok(bytes.len() as u64)
            }
            trames_vfs::FileValue::Stat(stat) => {
                let Self::Stat(address) = self else {
                    unreachable!("accepted stat output")
                };
                Linux::check(memory, *address, 128, Access::Write)?;
                memory.write(*address, &stat).map_err(|_| Errno(14))?;
                Ok(0)
            }
        }
    }
}
#[derive(Clone)]
pub struct FilePending {
    pub result: Arc<FileResult>,
    pub output: FileOutput,
    _target: Option<trames_vfs::FileTarget>,
    waiting: Option<Arc<Mutex<Option<trames_vfs::FileWork>>>>,
}
impl FilePending {
    pub fn interruptible(&self) -> bool {
        self.waiting
            .as_ref()
            .is_some_and(|w| w.lock().unwrap().is_some())
    }
    pub(super) fn native_wait_fds(&self) -> Vec<trames_vfs::HostFd> {
        self.waiting.as_ref().map_or_else(Vec::new, |w| {
            w.lock()
                .unwrap()
                .as_ref()
                .map_or_else(Vec::new, trames_vfs::FileWork::transfer_native_fds)
        })
    }
    pub fn new(
        result: Arc<FileResult>,
        output: FileOutput,
        target: impl Into<Option<trames_vfs::FileTarget>>,
    ) -> Self {
        Self {
            result,
            output,
            _target: target.into(),
            waiting: None,
        }
    }
}
pub enum FileBoundary {
    Owner {
        work: trames_vfs::FileWork,
        output: FileOutput,
    },
    Layout {
        work: trames_vfs::FileWork,
        output: FileOutput,
    },
    Signal {
        value: Result<u64, Errno>,
    },
}
#[derive(Clone)]
pub struct FileCheckpoint(Arc<Mutex<Option<FileBoundary>>>);
impl FileCheckpoint {
    fn new(boundary: FileBoundary) -> Self {
        Self(Arc::new(Mutex::new(Some(boundary))))
    }
    pub fn layout_domains(&self) -> Option<Vec<u64>> {
        self.0
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|boundary| match boundary {
                FileBoundary::Layout { work, .. } => Some(work.layout_domains()),
                _ => None,
            })
    }
    pub fn take(self) -> FileBoundary {
        self.0
            .lock()
            .unwrap()
            .take()
            .expect("one accepted file checkpoint")
    }
}
pub(super) struct PreparedFileCall {
    pub number: u32,
    pub args: [u64; 6],
    action: PreparedAction,
}
enum PreparedAction {
    Owner {
        work: trames_vfs::FileWork,
        output: FileOutput,
    },
    Host {
        work: trames_vfs::FileWork,
        output: FileOutput,
    },
    Layout {
        work: trames_vfs::FileWork,
        output: FileOutput,
    },
    Reply {
        reply: trames_vfs::FileReply,
        output: FileOutput,
    },
}
impl DirectSyscalls {
    pub fn file_call(number: u32) -> bool {
        namespace::supported(number)
            || matches!(number, 45..=47 | 56 | 62..=71 | 76 | 80..=83 | 267 | 285..=287 | 437)
    }
    pub fn start_file_call(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        if !Self::file_call(number) {
            return None;
        }
        if namespace::supported(number) {
            if let Some(value) = self.invoke_namespace(number, args, memory) {
                return Some(IoAttempt::Complete(value));
            }
            return self.start_prepared_file(number, args, memory, pid, target);
        }
        if number == 45 {
            if self.file_prepared(number, args) {
                return self.start_prepared_file(number, args, memory, pid, target);
            }
            let path = match Linux::path(memory, args[0]) {
                Ok(path) => path,
                Err(error) => return Some(IoAttempt::Complete(Err(error))),
            };
            let work = match self.paths.as_ref()?.truncate_path_work(&path, args[1])? {
                Ok(work) => work,
                Err(error) => return Some(IoAttempt::Complete(Err(error))),
            };
            return match self.prepare_open_work(number, args, work, memory) {
                Some(result) => Some(IoAttempt::Complete(result)),
                None => self.start_prepared_file(number, args, memory, pid, target),
            };
        }
        if let Some(value) = self.invoke_file_io(number, args, memory) {
            return Some(IoAttempt::Complete(value));
        }
        if matches!(number, 56 | 437) {
            if let Some(value) = self.invoke_path(number, args, memory) {
                return Some(IoAttempt::Complete(value));
            }
        }
        self.start_prepared_file(number, args, memory, pid, target)
    }
    pub(super) fn prepare_open_work(
        &self,
        number: u32,
        args: [u64; 6],
        work: trames_vfs::FileWork,
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        self.prepare_filesystem_work(number, args, work, FileOutput::None, memory)
    }
    pub(super) fn prepare_filesystem_work(
        &self,
        number: u32,
        args: [u64; 6],
        work: trames_vfs::FileWork,
        output: FileOutput,
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        let action = if work.host_work() {
            PreparedAction::Host { work, output }
        } else {
            match work.run() {
                trames_vfs::FileOutcome::Complete(reply)
                    if !reply.file_size_signal || self.task_signal.is_some() =>
                {
                    return Some(self.finish_file_reply(reply, output, memory));
                }
                trames_vfs::FileOutcome::Complete(reply) => PreparedAction::Reply { reply, output },
                trames_vfs::FileOutcome::Layout(work) => PreparedAction::Layout { work, output },
                trames_vfs::FileOutcome::Owner(work) => PreparedAction::Owner { work, output },
                trames_vfs::FileOutcome::Waiting(work) => PreparedAction::Host { work, output },
            }
        };
        *self.file_prepared.borrow_mut() = Some(PreparedFileCall {
            number,
            args,
            action,
        });
        None
    }
    pub(super) fn prepare_file_fallback(
        &self,
        number: u32,
        args: [u64; 6],
        target: trames_vfs::FileTarget,
        command: trames_vfs::FileCommand,
        output: FileOutput,
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        let paths = self.paths.as_ref()?;
        let action = if target.host_work(&command) {
            PreparedAction::Host {
                work: trames_vfs::FileWork::new(paths, target, command),
                output,
            }
        } else {
            match trames_vfs::FileWork::run_inline(paths, target, command) {
                trames_vfs::FileOutcome::Complete(reply)
                    if !reply.file_size_signal || self.task_signal.is_some() =>
                {
                    return Some(self.finish_file_reply(reply, output, memory));
                }
                trames_vfs::FileOutcome::Complete(reply) => PreparedAction::Reply { reply, output },
                trames_vfs::FileOutcome::Layout(work) => PreparedAction::Layout { work, output },
                trames_vfs::FileOutcome::Owner(work) => PreparedAction::Owner { work, output },
                trames_vfs::FileOutcome::Waiting(work) => PreparedAction::Host { work, output },
            }
        };
        *self.file_prepared.borrow_mut() = Some(PreparedFileCall {
            number,
            args,
            action,
        });
        None
    }
    fn complete_file_attempt(
        &self,
        reply: trames_vfs::FileReply,
        output: FileOutput,
        memory: &mut impl CpuMemory,
    ) -> IoAttempt {
        let owner_signal = reply.file_size_signal && self.task_signal.is_none();
        let value = self.finish_file_reply(reply, output, memory);
        if owner_signal {
            IoAttempt::FileCheckpoint(FileCheckpoint::new(FileBoundary::Signal { value }))
        } else {
            IoAttempt::Complete(value)
        }
    }
    fn finish_file_reply(
        &self,
        mut reply: trames_vfs::FileReply,
        output: FileOutput,
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        if reply.file_size_signal {
            if let Some(task) = &self.task_signal {
                task.raise(25);
            }
        }
        if let Some(bytes) = reply.scratch.take() {
            *self.scratch.borrow_mut() = bytes;
        }
        self.completed.set(self.completed.get() + 1);
        self.file_completed.set(self.file_completed.get() + 1);
        let transfer = matches!(output, FileOutput::CopyOffsets { .. });
        let result = output.apply(reply.result, memory);
        if transfer && result == Err(Errno(32)) {
            if let Some(task) = &self.task_signal {
                task.raise(13);
            }
        }
        result
    }
    pub(super) fn file_prepared(&self, number: u32, args: [u64; 6]) -> bool {
        self.file_prepared
            .borrow()
            .as_ref()
            .is_some_and(|c| c.number == number && c.args == args)
    }
    pub(super) fn start_prepared_file(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        if !self.file_prepared(number, args) {
            return None;
        }
        let accepted = self.file_prepared.borrow_mut().take().unwrap();
        Some(match accepted.action {
            PreparedAction::Layout { work, output } => {
                IoAttempt::FileCheckpoint(FileCheckpoint::new(FileBoundary::Layout {
                    work,
                    output,
                }))
            }
            PreparedAction::Reply { reply, output } => {
                self.complete_file_attempt(reply, output, memory)
            }
            PreparedAction::Owner { work, output } => {
                IoAttempt::FileCheckpoint(FileCheckpoint::new(FileBoundary::Owner { work, output }))
            }
            PreparedAction::Host { work, output } => {
                self.submit_file_work(work, output, number, args, memory, pid, target)
            }
        })
    }
    #[allow(clippy::too_many_arguments)] // Original accepted ABI/output plus source wake target.
    fn submit_file_work(
        &self,
        work: trames_vfs::FileWork,
        output: FileOutput,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let result = Arc::new(FileResult::default());
        let original = work.target().cloned();
        let signal = IoSignal::new(pid, target.clone());
        let subscriptions = vec![result.subscribe(&signal)];
        if work.transfer_waiting() {
            result.complete(trames_vfs::FileOutcome::Waiting(work));
        } else if work.host_work() {
            let Some(executor) = &self.file_executor else {
                return IoAttempt::FileCheckpoint(FileCheckpoint::new(FileBoundary::Layout {
                    work,
                    output,
                }));
            };
            executor.submit_file(work, result.clone());
        } else {
            result.complete(work.run());
        }
        self.resume_file(
            FilePending::new(result, output, original),
            number,
            args,
            signal,
            subscriptions,
            memory,
            target,
        )
    }
    #[allow(clippy::too_many_arguments)] // Caller-owned VFS/Memory, no retained references cross host work.
    pub fn start_owned_file(
        &self,
        vfs: &mut trames_vfs::Vfs,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        if namespace::supported(number) {
            let (call, output) = match namespace::import(number, args, memory) {
                Ok(call) => call,
                Err(error) => return Some(IoAttempt::Complete(Err(error))),
            };
            if !vfs.namespace_host_work() {
                // All instruction views are joined here. Use the original
                // caller VFS directly, as before worker admission existed.
                return Some(IoAttempt::Complete(output.apply(call.execute(vfs), memory)));
            }
            let work = vfs.path_queries().namespace_work(call);
            if let Some(value) = self.prepare_filesystem_work(number, args, work, output, memory) {
                return Some(IoAttempt::Complete(value));
            }
            return self.start_prepared_file(number, args, memory, pid, target);
        }
        if number == 45 {
            let path = match Linux::path(memory, args[0]) {
                Ok(path) => path,
                Err(error) => return Some(IoAttempt::Complete(Err(error))),
            };
            let work = match vfs.path_queries().truncate_path_work(&path, args[1])? {
                Ok(work) => work,
                Err(error) => return Some(IoAttempt::Complete(Err(error))),
            };
            return Some(self.submit_file_work(
                work,
                FileOutput::None,
                number,
                args,
                memory,
                pid,
                target,
            ));
        }
        if number == 81 {
            return Some(self.submit_file_work(
                trames_vfs::FileWork::sync_all(vfs.path_queries()),
                FileOutput::None,
                number,
                args,
                memory,
                pid,
                target,
            ));
        }
        if matches!(number, 56 | 437) {
            let paths = vfs.path_queries();
            let decoded = (|| {
                let (flags, mode, policy) = if number == 437 {
                    Linux::decode_open_how(memory, args[2], args[3])?
                } else {
                    (args[2] as u32, args[3] as u32, 0)
                };
                Ok((Linux::path(memory, args[1])?, flags, mode, policy))
            })();
            let (path, flags, mode, policy) = match decoded {
                Ok(value) => value,
                Err(error) => return Some(IoAttempt::Complete(Err(error))),
            };
            match paths.open_at_resolve(args[0] as i32, &path, flags, mode, policy, &self.files) {
                Some(result) => return Some(IoAttempt::Complete(result.map(u64::from))),
                None => {
                    let work = paths.take_open_work()?;
                    return match self.prepare_open_work(number, args, work, memory) {
                        Some(result) => Some(IoAttempt::Complete(result)),
                        None => self.start_prepared_file(number, args, memory, pid, target),
                    };
                }
            }
        }
        let (file, command, output) = if matches!(number, 71 | 76 | 285) {
            let (file, command, output) = copy_import(&vfs.shared_files(), number, args, memory)?;
            let command = match command {
                Ok(command) => command,
                Err(error) => return Some(IoAttempt::Complete(Err(error))),
            };
            (file, command, output)
        } else {
            if !matches!(number, 46 | 47 | 62..=70 | 80 | 82 | 83 | 267 | 286 | 287) {
                return None;
            }
            let original = vfs.shared_files().lookup(args[0] as u32)?.ok()?;
            let file = if matches!(number, 82 | 83 | 267) {
                original.filesystem_target()
            } else {
                original.file_target()?
            };
            let (command, output) =
                match import(number, args, memory, &mut self.scratch.borrow_mut()) {
                    Ok(call) => call,
                    Err(error) => return Some(IoAttempt::Complete(Err(error))),
                };
            (file, command, output)
        };
        Some(if file.host_work_owned(&command) {
            self.submit_file_work(
                trames_vfs::FileWork::from_vfs(vfs, file, command),
                output,
                number,
                args,
                memory,
                pid,
                target,
            )
        } else {
            match trames_vfs::FileWork::run_owned(vfs, file, command) {
                trames_vfs::FileOutcome::Complete(reply) => {
                    self.complete_file_attempt(reply, output, memory)
                }
                trames_vfs::FileOutcome::Waiting(work) => {
                    self.submit_file_work(work, output, number, args, memory, pid, target)
                }
                _ => unreachable!("joined caller layout ownership"),
            }
        })
    }
    #[allow(clippy::too_many_arguments)] // Accepted ABI/output and its source memory/wake subscription.
    pub(super) fn resume_file(
        &self,
        pending: FilePending,
        number: u32,
        args: [u64; 6],
        signal: Arc<IoSignal>,
        subscriptions: Vec<IoSubscription>,
        memory: &mut impl CpuMemory,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let waiting = pending
            .waiting
            .as_ref()
            .and_then(|w| w.lock().unwrap().take());
        if let Some(work) = waiting {
            if !work.transfer_ready() {
                return self.park_transfer(pending, work, number, args, signal, memory, target);
            }
            pending.result.begin();
            if work.host_work() {
                let Some(executor) = &self.file_executor else {
                    return IoAttempt::FileCheckpoint(FileCheckpoint::new(FileBoundary::Layout {
                        work,
                        output: pending.output,
                    }));
                };
                executor.submit_file(work, pending.result.clone());
            } else {
                pending.result.complete(work.run());
            }
        }
        match pending.result.take() {
            Some(trames_vfs::FileOutcome::Waiting(work)) => {
                self.park_transfer(pending, work, number, args, signal, memory, target)
            }
            Some(trames_vfs::FileOutcome::Complete(reply)) => {
                self.complete_file_attempt(reply, pending.output, memory)
            }
            Some(trames_vfs::FileOutcome::Owner(work)) => {
                IoAttempt::FileCheckpoint(FileCheckpoint::new(FileBoundary::Owner {
                    work,
                    output: pending.output,
                }))
            }
            Some(trames_vfs::FileOutcome::Layout(work)) => {
                IoAttempt::FileCheckpoint(FileCheckpoint::new(FileBoundary::Layout {
                    work,
                    output: pending.output,
                }))
            }
            None => IoAttempt::Blocked(PendingIo {
                aio: None,
                number,
                args,
                deadline: None,
                signal,
                flock: None,
                retained_byte: None,
                retained_socket: None,
                native_tcp: None,
                resource_deadline: None,
                retained_poll: None,
                epoll_revision: None,
                _subscriptions: subscriptions,
                host_subscription: None,
                socket_subscriptions: Vec::new(),
                uring: None,
                poll_uring: None,
                file: Some(pending),
                target: target.clone(),
            }),
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn park_transfer(
        &self,
        mut pending: FilePending,
        work: trames_vfs::FileWork,
        number: u32,
        args: [u64; 6],
        signal: Arc<IoSignal>,
        memory: &mut impl CpuMemory,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let _ = memory;
        signal.reset();
        let wait = match work.transfer_wait_sources(&signal) {
            Ok(wait) => wait,
            Err(_) => return self.complete(number, args, Err(Errno(5))),
        };
        let mut subscriptions = vec![pending.result.subscribe(&signal)];
        subscriptions.extend(wait.subscriptions);
        let mut native = Vec::new();
        if let Some(events) = target.upgrade().and_then(|t| t.host_events()) {
            for (fd, write) in wait.native {
                match events.subscribe(fd, write, &signal) {
                    Ok(s) => native.push(s),
                    Err(_) => return self.complete(number, args, Err(Errno(5))),
                }
            }
        }
        if work.transfer_ready() {
            signal.notify();
        }
        pending.result.begin();
        *pending
            .waiting
            .get_or_insert_with(Arc::default)
            .lock()
            .unwrap() = Some(work);
        IoAttempt::Blocked(PendingIo {
            aio: None,
            number,
            args,
            deadline: None,
            signal,
            flock: None,
            retained_byte: None,
            retained_socket: None,
            native_tcp: None,
            resource_deadline: wait.deadline,
            retained_poll: None,
            epoll_revision: None,
            _subscriptions: subscriptions,
            host_subscription: None,
            socket_subscriptions: native,
            uring: None,
            poll_uring: None,
            file: Some(pending),
            target: target.clone(),
        })
    }
    pub fn start_retained_file(
        &self,
        pending: FilePending,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let signal = IoSignal::new(pid, target.clone());
        let subscriptions = vec![pending.result.subscribe(&signal)];
        self.resume_file(pending, number, args, signal, subscriptions, memory, target)
    }
}

pub(super) fn import(
    number: u32,
    a: [u64; 6],
    memory: &impl CpuMemory,
    scratch: &mut Vec<u8>,
) -> Result<(trames_vfs::FileCommand, FileOutput), Errno> {
    use trames_vfs::FileCommand as Command;
    let offset = (matches!(number, 67..=70) || matches!(number, 286 | 287) && a[3] != u64::MAX)
        .then_some(a[3]);
    if matches!(number, 286 | 287) && a[5] & !6 != 0 {
        return Err(Errno(95));
    }
    match number {
        62 => Ok((
            Command::Seek {
                offset: a[1] as i64,
                whence: a[2] as u32,
            },
            FileOutput::None,
        )),
        63 | 67 => {
            let count = Linux::read_parameters(a, memory)?;
            Ok((Command::Read { count, offset }, FileOutput::Scalar(a[1])))
        }
        65 | 69 | 286 => {
            let (parts, count) = if number == 65 || number == 286 && offset.is_none() {
                Linux::readv_parts(memory, a)?
            } else {
                Linux::positioned_vector_parts(memory, a, false)?
            };
            Ok((Command::Read { count, offset }, FileOutput::Vectors(parts)))
        }
        64 | 68 => {
            let count = a[2].min(crate::MAX_WRITE as u64) as usize;
            Linux::check(memory, a[1], count, Access::Read)?;
            scratch.resize(count, 0);
            memory.read(a[1], scratch).map_err(|_| Errno(14))?;
            Ok((
                Command::Write {
                    bytes: std::mem::take(scratch),
                    offset,
                },
                FileOutput::None,
            ))
        }
        66 | 70 | 287 => {
            if number == 66 || number == 287 && offset.is_none() {
                Linux::writev_parameters(a, memory, scratch)?;
            } else {
                let (parts, count) = Linux::positioned_vector_parts(memory, a, true)?;
                Linux::gather_parts(memory, &parts, count, scratch)?;
            }
            let bytes = std::mem::take(scratch);
            Ok((
                if number == 287 && a[5] & 6 != 0 {
                    Command::WriteSync {
                        bytes,
                        offset,
                        data_only: a[5] & 4 == 0,
                    }
                } else {
                    Command::Write { bytes, offset }
                },
                FileOutput::None,
            ))
        }
        46 => Ok((Command::Truncate(a[1]), FileOutput::None)),
        47 => Ok((
            Command::Allocate {
                mode: a[1],
                offset: a[2],
                length: a[3],
            },
            FileOutput::None,
        )),
        80 => Ok((Command::Stat, FileOutput::Stat(a[1]))),
        82 | 83 => Ok((
            Command::Sync {
                data_only: number == 83,
            },
            FileOutput::None,
        )),
        267 => Ok((Command::SyncFilesystem, FileOutput::None)),
        _ => unreachable!("file ABI classified before import"),
    }
}
impl DirectSyscalls {
    pub(super) fn invoke_file_io(
        &self,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if matches!(number, 71 | 76 | 285) {
            if self.file_prepared(number, a) {
                return None;
            }
            let (file, command, output) =
                copy_import(self.membership.as_ref()?, number, a, memory)?;
            return match command {
                Ok(command) => self.prepare_file_fallback(number, a, file, command, output, memory),
                Err(error) => Some(Err(error)),
            };
        }
        if number == 81 {
            if self.file_prepared(number, a) {
                return None;
            }
            let work = trames_vfs::FileWork::sync_all(self.paths.as_ref()?.retain_context());
            return self.prepare_open_work(number, a, work, memory);
        }
        if !matches!(number, 46 | 47 | 62..=70 | 80 | 82 | 83 | 267 | 286 | 287) {
            return None;
        }
        if self.file_prepared(number, a) {
            return None;
        }
        let access = if matches!(number, 82 | 83 | 267) {
            self.membership
                .as_ref()?
                .lookup(a[0] as u32)?
                .ok()
                .map(|f| trames_vfs::FileAccess::Full(f.filesystem_target()))
        } else {
            self.files.resolve(a[0] as u32).or_else(|| {
                self.membership
                    .as_ref()?
                    .lookup(a[0] as u32)?
                    .ok()?
                    .file_target()
                    .map(trames_vfs::FileAccess::Full)
            })
        }?;
        let (fast, target) = match access {
            trames_vfs::FileAccess::Fast(file) => {
                let target = file.target();
                (Some(file), target)
            }
            trames_vfs::FileAccess::Full(target) => (None, Some(target)),
        };
        let (mut command, output) = match import(number, a, memory, &mut self.scratch.borrow_mut())
        {
            Ok(prepared) => prepared,
            Err(error) => {
                self.completed.set(self.completed.get() + 1);
                self.file_completed.set(self.file_completed.get() + 1);
                return Some(Err(error));
            }
        };
        let result = fast.as_ref().and_then(|file| {
            use trames_vfs::{FileCommand as Command, FileValue as Value};
            match &command {
                Command::Read { count, offset } => file
                    .read(*count, *offset, &mut self.disk_cache.borrow_mut())
                    .map(|r| r.map(Value::Bytes)),
                Command::Write { bytes, offset } => file
                    .write(bytes, *offset, &mut self.disk_cache.borrow_mut())
                    .map(|r| r.map(|n| Value::Count(n as u64))),
                Command::Seek { offset, whence } => {
                    file.seek(*offset, *whence).map(|r| r.map(Value::Count))
                }
                Command::Stat => Some(file.stat().map(Value::Stat)),
                _ => None,
            }
        });
        if let Some(result) = result {
            let scratch = match &mut command {
                trames_vfs::FileCommand::Write { bytes, .. } => Some(std::mem::take(bytes)),
                _ => None,
            };
            return Some(self.finish_file_reply(
                trames_vfs::FileReply {
                    result,
                    file_size_signal: false,
                    scratch,
                },
                output,
                memory,
            ));
        }
        self.prepare_file_fallback(number, a, target?, command, output, memory)
    }
}

fn copy_import(
    files: &trames_vfs::SharedFiles,
    number: u32,
    a: [u64; 6],
    memory: &impl CpuMemory,
) -> Option<(
    trames_vfs::FileTarget,
    Result<trames_vfs::FileCommand, Errno>,
    FileOutput,
)> {
    let range = number == 285;
    let splice = number == 76;
    let (input, output, from, to, count, flags) = if splice {
        (a[0], a[2], a[1], a[3], a[4], a[5] as u32)
    } else if range {
        (a[0], a[2], a[1], a[3], a[4], 0)
    } else {
        (a[1], a[0], a[2], 0, a[3], 0)
    };
    // Resolve each original OFD once. A concurrent close/reuse must not retarget
    // a pair already accepted while deciding between file and stream work.
    let input = files.lookup(input as u32)?.ok()?;
    let output = files.lookup(output as u32)?.ok()?;
    let offset = |pointer| -> Result<Option<u64>, Errno> {
        if pointer == 0 {
            return Ok(None);
        }
        Linux::check(memory, pointer, 8, Access::Read)?;
        Linux::check(memory, pointer, 8, Access::Write)?;
        let value = memory.read_u64(pointer).map_err(|_| Errno(14))?;
        if value > i64::MAX as u64 {
            Err(Errno(22))
        } else {
            Ok(Some(value))
        }
    };
    if (splice || !range && (input.file_target().is_none() || output.file_target().is_none()))
        && trames_vfs::StreamTransfer::admitted(&input, &output)
    {
        let target = output.filesystem_target();
        let command =
            trames_vfs::FileCommand::Transfer(RefCell::new(trames_vfs::StreamTransfer::new(
                input,
                output,
                offset(from),
                offset(to),
                count,
                splice,
                flags,
            )));
        return Some((target, Ok(command), FileOutput::CopyOffsets { from, to }));
    }
    if splice {
        return None;
    }
    let input = input.file_target()?;
    let output = output.file_target()?;
    let command = if range && a[5] != 0 {
        Err(Errno(22))
    } else {
        Ok(trames_vfs::FileCommand::Copy {
            input,
            transfer: RefCell::new(trames_vfs::FileCopy::new(
                offset(from),
                offset(to),
                count,
                range,
            )),
        })
    };
    Some((output, command, FileOutput::CopyOffsets { from, to }))
}

#[cfg(test)]
#[path = "file_tests.rs"]
mod tests;
