// SPDX-License-Identifier: GPL-3.0-or-later
//! Source-worker file calls and direct completion from the existing disk pool.
use super::*;
use std::sync::Mutex;
#[path = "file_copyout.rs"]
mod copyout;
pub(super) use copyout::FileCopyout;
#[cfg(test)]
#[path = "file_copyout_tests.rs"]
pub(crate) mod copyout_tests;

pub trait FileExecutor: Send + Sync {
    fn submit_file(&self, job: trames_vfs::FileWork, result: Arc<FileResult>);
    fn submit_host(
        &self,
        job: Box<dyn crate::HostFileTask>,
        _exclusive: Option<trames_memory::layout::LayoutExclusive>,
    ) {
        job.fail();
    }
}
#[derive(Default)]
pub struct FileResult {
    result: Mutex<FileResultState>,
    readiness: Arc<trames_vfs::Readiness>,
    owner: std::sync::OnceLock<std::thread::Thread>,
    finished: std::sync::atomic::AtomicBool,
}
#[derive(Default)]
struct FileResultState {
    outcome: Option<trames_vfs::FileOutcome>,
    target: Option<trames_vfs::FileTarget>,
    cancelled: bool,
    // Only abandoned native work needs a completion-held release. It owns no
    // guest pointer and runs its cleanup on the existing completing thread.
    release: Option<Box<dyn Send>>,
    notifiers: Vec<Box<dyn FnOnce() + Send>>,
}
impl FileResult {
    pub fn wake_joined() -> Self {
        Self {
            owner: std::sync::OnceLock::from(std::thread::current()),
            ..Default::default()
        }
    }
    pub fn complete(&self, result: trames_vfs::FileOutcome) {
        let mut state = self.result.lock().unwrap();
        let discarded = if state.cancelled {
            Some(result)
        } else {
            state.outcome.replace(result)
        };
        let release = state.release.take();
        let notifiers = std::mem::take(&mut state.notifiers);
        self.finished
            .store(true, std::sync::atomic::Ordering::Release);
        drop(state);
        let release = Self::defer_fuse_release(&discarded, release);
        // Replies can own original positions, FUSE requests and AIO credits.
        // Their readiness callbacks must run outside this completion mutex.
        drop(discarded);
        drop(release);
        for notify in notifiers {
            notify();
        }
        self.readiness.notify_locked();
        if let Some(owner) = self.owner.get() {
            owner.unpark();
        }
    }
    pub fn fail(&self, errno: u32) {
        self.complete(trames_vfs::FileOutcome::Complete(trames_vfs::FileReply {
            resources: Default::default(),
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
    pub(crate) fn on_finished(&self, notify: Box<dyn FnOnce() + Send>) {
        let notify = {
            let mut state = self.result.lock().unwrap();
            if self.finished.load(std::sync::atomic::Ordering::Relaxed) {
                Some(notify)
            } else {
                state.notifiers.push(notify);
                None
            }
        };
        if let Some(notify) = notify {
            notify();
        }
    }
    pub fn wake_owner(&self) {
        let _ = self.owner.set(std::thread::current());
    }
    pub fn ready(&self) -> bool {
        let state = self.result.lock().unwrap();
        state.cancelled || state.outcome.is_some()
    }
    pub(super) fn take(&self) -> Option<trames_vfs::FileOutcome> {
        let (outcome, target) = {
            let mut state = self.result.lock().unwrap();
            let outcome = state.outcome.take();
            let target = outcome.as_ref().and_then(|_| state.target.take());
            (outcome, target)
        };
        drop(target);
        outcome
    }
    pub fn cancelled(&self) -> bool {
        self.result.lock().unwrap().cancelled
    }
    pub(super) fn abandon(&self, release: Option<Box<dyn Send>>, native_pending: bool) {
        let mut state = self.result.lock().unwrap();
        state.cancelled = true;
        let outcome = state.outcome.take();
        let target = state.target.take();
        let deferred = native_pending
            && outcome.is_none()
            && !self.finished.load(std::sync::atomic::Ordering::Relaxed);
        let release = if deferred {
            // A batch drains each original request once, even when its caller
            // kept snapshots. A later generic cancel cannot take this credit.
            debug_assert!(release.is_none() || state.release.is_none());
            if release.is_some() {
                state.release = release;
            }
            None
        } else {
            release
        };
        drop(state);
        let release = Self::defer_fuse_release(&outcome, release);
        drop(outcome);
        drop(target);
        drop(release);
        self.readiness.notify_locked();
        if let Some(owner) = self.owner.get() {
            owner.unpark();
        }
    }
    fn defer_fuse_release(
        outcome: &Option<trames_vfs::FileOutcome>,
        release: Option<Box<dyn Send>>,
    ) -> Option<Box<dyn Send>> {
        let lease = release?;
        match outcome {
            Some(trames_vfs::FileOutcome::Waiting(work)) => match work.fuse_signal_request() {
                Some(request) => request.retain_cancellation(lease),
                None => Some(lease),
            },
            _ => Some(lease),
        }
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> trames_vfs::IoSubscription {
        self.readiness.subscribe(signal)
    }
}

#[derive(Clone)]
pub enum FileOutput {
    SocketPath(Box<RetainedSocket>),
    LocalMessage(Box<RetainedByte>),
    Directory(u64),
    Readlink(u64, u64),
    FuseStat(u32, [u64; 6]),
    None,
    Write,
    Scalar(u64),
    MountQuery {
        address: u64,
        list: bool,
    },
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
        // Standalone synchronous embeddings retain their existing errno API.
        // Scheduler paths use FilePending and retain the accepted copy cursor.
        FileCopyout::new(self, result)
            .progress(memory)
            .unwrap_or(Err(Errno(14)))
    }
}
#[derive(Clone)]
pub struct FilePending {
    pub result: Arc<FileResult>,
    pub output: FileOutput,
    waiting: Option<Arc<Mutex<Option<trames_vfs::FileWork>>>>,
    copyout: Option<Arc<Mutex<Option<FileCopyout>>>>,
    input: Option<Arc<Mutex<Option<super::file_input::Accepted>>>>,
}
impl FilePending {
    pub(crate) fn uring_input_submitted(&self) -> Option<u32> {
        let slot = self.input.as_ref()?.lock().unwrap();
        match slot.as_ref()? {
            super::file_input::Accepted::UringEnter(call) => Some(call.submitted()),
            _ => None,
        }
    }
    pub fn cancel_import(&self) {
        let accepted = self
            .input
            .as_ref()
            .and_then(|input| input.lock().unwrap().take());
        let work = self
            .waiting
            .as_ref()
            .and_then(|waiting| waiting.lock().unwrap().take());
        let copy = self
            .copyout
            .as_ref()
            .and_then(|copy| copy.lock().unwrap().take())
            .map(|mut copy| copy.cancel());
        self.result.abandon(None, false);
        drop(accepted);
        drop(work);
        drop(copy);
    }
    fn copyout(copy: FileCopyout) -> Self {
        Self {
            result: Arc::default(),
            output: FileOutput::None,
            waiting: None,
            copyout: Some(Arc::new(Mutex::new(Some(copy)))),
            input: None,
        }
    }
    pub fn fuse_interrupt_needed(&self) -> bool {
        self.waiting.as_ref().is_some_and(|w| {
            w.lock()
                .unwrap()
                .as_ref()
                .is_some_and(|w| w.fuse_interrupt_needed())
        })
    }
    pub fn fuse_interrupt(&self) {
        let request = self.waiting.as_ref().and_then(|w| {
            w.lock()
                .unwrap()
                .as_ref()
                .and_then(|work| work.fuse_signal_request())
        });
        if let Some(request) = request {
            request.interrupt();
        }
    }
    pub fn interruptible(&self) -> bool {
        if self.input.as_ref().is_some_and(|input| {
            input.lock().unwrap().as_ref().is_some_and(|input|
            matches!(input,super::file_input::Accepted::Ioctl(call) if call.interruptible()))
        }) {
            return true;
        }
        self.waiting.as_ref().is_some_and(|w| {
            w.lock()
                .unwrap()
                .as_ref()
                .is_some_and(trames_vfs::FileWork::interruptible_wait)
        })
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
        result.result.lock().unwrap().target = target.into();
        Self {
            result,
            output,
            waiting: None,
            copyout: None,
            input: None,
        }
    }
}
pub enum FileBoundary {
    WaitInput(Box<super::event_input::WaitInput>),
    EpollControl {
        fd: u32,
        op: u32,
        target: u32,
        events: u32,
        data: u64,
    },
    Registration(Box<super::uring::Registration>),
    UringEnter(Box<super::uring::EnterInput>),
    Aio(super::aio::RetainedAio),
    AioLookup(Box<super::aio::lookup::Lookup>),
    AioSetup(Box<super::aio::SetupInput>),
    TimerFd(Box<super::timer_control::TimerControl>),
    Ioctl(Box<super::ioctl_control::IoctlControl>),
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
    pub(crate) fn uring_submitted(&self) -> Option<u32> {
        match self.0.lock().unwrap().as_ref()? {
            FileBoundary::UringEnter(call) => Some(call.submitted()),
            _ => None,
        }
    }
    pub(super) fn new(boundary: FileBoundary) -> Self {
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
            .unwrap_or(FileBoundary::Signal {
                value: Err(Errno(4)),
            })
    }
    pub fn cancel(&self) {
        let accepted = self.0.lock().unwrap().take();
        drop(accepted);
    }
}
pub(super) struct PreparedFileCall {
    pub number: u32,
    pub args: [u64; 6],
    pub(super) action: PreparedAction,
}
#[allow(clippy::large_enum_variant)] // Prepared calls own their cold resource state without another allocation.
pub(super) enum PreparedAction {
    EpollControl(Box<trames_vfs::EpollControl>),
    Checkpoint(FileCheckpoint),
    Input(Box<super::file_input::Accepted>, trames_memory::PageFault),
    Fifo(trames_vfs::FifoOpen),
    Copyout(Box<FileCopyout>),
    Byte(RetainedByte),
    Socket(RetainedSocket),
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
type ImportedFileInput = (
    Result<(trames_vfs::FileCommand, FileOutput), Errno>,
    Option<(super::file_input::Input, trames_memory::PageFault)>,
);
impl DirectSyscalls {
    #[allow(clippy::too_many_arguments)]
    fn import_file_input(
        &self,
        paths: impl FnOnce() -> trames_vfs::PathQueries,
        file: &trames_vfs::FileTarget,
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
        regular: bool,
        unsigned: bool,
    ) -> ImportedFileInput {
        if !memory.async_faults_possible() || !matches!(number, 63..=70 | 286 | 287) {
            return (
                import(
                    number,
                    args,
                    memory,
                    &mut self.scratch.borrow_mut(),
                    regular,
                    unsigned,
                ),
                None,
            );
        }
        let input = super::file_input::Input::new(paths(), file.clone(), regular, unsigned);
        let (result, fault) = input.read(number, args, memory, &mut self.scratch.borrow_mut());
        (result, fault.map(|fault| (input, fault)))
    }
    fn fifo_reply(
        &self,
        number: u32,
        reply: &trames_vfs::FileReply,
    ) -> Option<trames_vfs::FifoOpen> {
        if !matches!(number, 56 | 437) {
            return None;
        }
        let Ok(trames_vfs::FileValue::Count(fd)) = &reply.result else {
            return None;
        };
        self.paths.as_ref()?.pending_fifo_open(*fd as u32)
    }
    pub fn file_call(number: u32) -> bool {
        namespace::supported(number)
            || crate::file_advice::entry(number)
            || matches!(number, 45..=47 | 56 | 61..=71 | 76..=77 | 80..=84 | 227 | 267 | 285..=287 | 437)
    }
    pub fn file_entry(number: u32, args: [u64; 6]) -> bool {
        matches!(number, 21 | 57 | 59 | 199 | 425)
            || Self::file_call(number)
            || number == 25 && matches!(args[1], 1033 | 1034)
    }
    fn read_zero_file(
        &self,
        file: &trames_vfs::FileTarget,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        let read = match number {
            63 | 65 | 67 | 69 => number,
            286 if args[3] == u64::MAX => 65,
            286 => 69,
            _ => return None,
        };
        let result = file.read_zero_device(|| {
            Linux::copy_device_zeroes(read, args, memory, self.signal_reader.as_deref())
        })?;
        self.completed.set(self.completed.get() + 1);
        self.file_completed.set(self.file_completed.get() + 1);
        Some(result)
    }
    pub(super) fn close_membership(&self, args: [u64; 6]) -> Option<Result<u64, Errno>> {
        let files = self.membership.as_ref()?;
        let owner = self.lock_context.as_ref()?.owner;
        if let Some(paths) = &self.paths {
            if self.file_prepared(57, args) {
                return None;
            }
            match paths.close_file(files, args[0] as u32, owner)? {
                Ok(Some(work)) => {
                    *self.file_prepared.borrow_mut() = Some(PreparedFileCall {
                        number: 57,
                        args,
                        action: PreparedAction::Host {
                            work,
                            output: FileOutput::None,
                        },
                    });
                    None
                }
                other => Some(other.map(|_| 0)),
            }
        } else {
            files.close(args[0] as u32, owner).map(|r| r.map(|_| 0))
        }
    }
    pub fn start_file_call(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        if !Self::file_entry(number, args) {
            return None;
        }
        if number == 21 {
            if let Some(result) = self.invoke_epoll_control(number, args, memory) {
                return Some(IoAttempt::Complete(result));
            }
            return self.start_prepared_file(number, args, memory, pid, target);
        }
        if number == 57 {
            if let Some(value) = self.close_membership(args) {
                self.record_fd_control();
                return Some(IoAttempt::Complete(value));
            }
            return self.start_prepared_file(number, args, memory, pid, target);
        }
        if number == 227 {
            return self.start_memory_sync(args, memory, pid, target);
        }
        if namespace::supported(number) {
            if let Some(value) = self.invoke_namespace(number, args, memory) {
                return Some(IoAttempt::Complete(value));
            }
            return self.start_prepared_file(number, args, memory, pid, target);
        }
        if number == 45 {
            if args[1] > i64::MAX as u64 {
                return Some(IoAttempt::Complete(Err(Errno(22))));
            }
            if self.file_prepared(number, args) {
                return self.start_prepared_file(number, args, memory, pid, target);
            }
            if memory.async_faults_possible() {
                return match self.invoke_path_input(number, args, memory) {
                    Some(result) => Some(IoAttempt::Complete(result)),
                    None => self.start_prepared_file(number, args, memory, pid, target),
                };
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
        if matches!(number, 56 | 61 | 437) {
            if let Some(value) = self.invoke_path(number, args, memory) {
                return Some(IoAttempt::Complete(value));
            }
        }
        if let Some(attempt) = self.start_prepared_file(number, args, memory, pid, target) {
            return Some(attempt);
        }
        if matches!(number, 286 | 287) && args[3] == u64::MAX {
            return self.start(number, args, memory, pid, target, None);
        }
        None
    }
    pub(super) fn prepare_fifo_open(
        &self,
        number: u32,
        args: [u64; 6],
        open: trames_vfs::FifoOpen,
    ) {
        *self.file_prepared.borrow_mut() = Some(PreparedFileCall {
            number,
            args,
            action: PreparedAction::Fifo(open),
        });
    }
    fn start_fifo_open(
        &self,
        open: trames_vfs::FifoOpen,
        number: u32,
        args: [u64; 6],
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let pending = PendingIo {
            process_vm: None,
            binder: None,
            aio: None,
            message: None,
            number,
            args,
            deadline: None,
            signal: IoSignal::new(pid, target.clone()),
            flock: None,
            record: None,
            retained_byte: None,
            retained_socket: None,
            native_tcp: None,
            resource_deadline: None,
            retained_poll: None,
            epoll_revision: None,
            terminal_job: false,
            _subscriptions: Vec::new(),
            host_subscription: None,
            socket_subscriptions: Vec::new(),
            uring: None,
            poll_uring: None,
            file: None,
            fifo_open: Some(open),
            target: target.clone(),
        };
        self.resume_fifo_open(pending)
    }
    pub(super) fn resume_fifo_open(&self, mut pending: PendingIo) -> IoAttempt {
        pending.signal.reset();
        pending._subscriptions.clear();
        let open = pending.fifo_open.as_mut().unwrap();
        // Subscribe before deciding, so peer open/close cannot lose its wake.
        pending._subscriptions.push(open.subscribe(&pending.signal));
        match open.finish() {
            Some(value) => {
                self.file_completed.set(self.file_completed.get() + 1);
                self.complete(pending.number, pending.args, value.map(u64::from))
            }
            None => IoAttempt::Blocked(pending),
        }
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
                    if let Some(open) = self.fifo_reply(number, &reply) {
                        self.prepare_fifo_open(number, args, open);
                        return None;
                    }
                    return self.finish_file_reply(number, args, reply, output, memory);
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
        if let Some(result) = target.proc_io_local(&command, memory) {
            return self.finish_file_reply(
                number,
                args,
                trames_vfs::FileReply {
                    resources: trames_vfs::FileResources::file(&target),
                    result,
                    file_size_signal: false,
                    scratch: None,
                },
                output,
                memory,
            );
        }
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
                    return self.finish_file_reply(number, args, reply, output, memory);
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
    fn accept_file_reply(
        &self,
        mut reply: trames_vfs::FileReply,
        output: FileOutput,
    ) -> FileCopyout {
        let signal_owner = reply.file_size_signal && self.task_signal.is_none();
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
        let transfer = matches!(output, FileOutput::CopyOffsets { .. } | FileOutput::Write);
        if transfer && matches!(&reply.result, Err(Errno(32))) {
            if let Some(task) = &self.task_signal {
                task.raise(13);
            }
        }
        let mut copy = FileCopyout::new(&output, reply.result).retain(reply.resources);
        copy.signal_owner = signal_owner;
        copy
    }
    #[allow(clippy::too_many_arguments)] // Original accepted ABI and source notification context.
    fn complete_file_attempt(
        &self,
        reply: trames_vfs::FileReply,
        output: FileOutput,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        match output {
            FileOutput::SocketPath(mut call) => {
                if let Err(error) = call.accept_path(reply.result) {
                    return self.complete_socket(Err(error));
                }
                return self.start_retained_socket(*call, memory, pid, target);
            }
            FileOutput::LocalMessage(file) => {
                if let Err(error) = file.accept_datagram_path(reply.result) {
                    return IoAttempt::Complete(Err(error));
                }
                return self.start_retained_byte(*file, number, args, memory, pid, target);
            }
            _ => {}
        }
        self.deliver_copyout(
            self.accept_file_reply(reply, output),
            number,
            args,
            memory,
            pid,
            target,
        )
    }
    fn copyout_value(signal_owner: bool, value: Result<u64, Errno>) -> IoAttempt {
        if signal_owner {
            IoAttempt::FileCheckpoint(FileCheckpoint::new(FileBoundary::Signal { value }))
        } else {
            IoAttempt::Complete(value)
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn deliver_copyout(
        &self,
        mut copy: FileCopyout,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        match copy.progress(memory) {
            Ok(value) => Self::copyout_value(copy.signal_owner, value),
            Err(fault) => {
                let signal = IoSignal::new(pid, target.clone());
                Self::park_copyout(
                    FilePending::copyout(copy),
                    fault,
                    number,
                    args,
                    signal,
                    target,
                )
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn park_copyout(
        pending: FilePending,
        fault: trames_memory::PageFault,
        number: u32,
        args: [u64; 6],
        signal: Arc<IoSignal>,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        signal.reset();
        let subscriptions = vec![fault.wait.subscribe(&signal)];
        if fault.wait.ready() {
            signal.notify();
        }
        Self::wait_file(pending, number, args, signal, subscriptions, target)
    }
    /// Immediate file entry can defer before handing its result to the event
    /// path. Store the original result/cursor, never the operation to replay.
    pub(super) fn finish_file_reply(
        &self,
        number: u32,
        args: [u64; 6],
        reply: trames_vfs::FileReply,
        output: FileOutput,
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        match output {
            FileOutput::SocketPath(mut call) => {
                if let Err(error) = call.accept_path(reply.result) {
                    return Some(Err(error));
                }
                *self.file_prepared.borrow_mut() = Some(PreparedFileCall {
                    number,
                    args,
                    action: PreparedAction::Socket(*call),
                });
                return None;
            }
            FileOutput::LocalMessage(file) => {
                if let Err(error) = file.accept_datagram_path(reply.result) {
                    return Some(Err(error));
                }
                self.prepare_retained_byte(number, args, *file);
                return None;
            }
            _ => {}
        }
        self.finish_file_copyout(number, args, self.accept_file_reply(reply, output), memory)
    }
    pub(super) fn finish_file_copyout(
        &self,
        number: u32,
        args: [u64; 6],
        mut copy: FileCopyout,
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        match copy.progress(memory) {
            Ok(value) => Some(value),
            Err(_) => {
                *self.file_prepared.borrow_mut() = Some(PreparedFileCall {
                    number,
                    args,
                    action: PreparedAction::Copyout(Box::new(copy)),
                });
                None
            }
        }
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
            PreparedAction::EpollControl(call) => {
                self.start_retained_epoll_control(call, args, pid, target)
            }
            PreparedAction::Checkpoint(call) => IoAttempt::FileCheckpoint(call),
            PreparedAction::Input(input, fault) => {
                self.park_input(*input, fault, number, args, pid, target)
            }
            PreparedAction::Copyout(copy) => {
                self.deliver_copyout(*copy, number, args, memory, pid, target)
            }
            PreparedAction::Fifo(open) => self.start_fifo_open(open, number, args, pid, target),
            PreparedAction::Socket(call) => self.start_retained_socket(call, memory, pid, target),
            PreparedAction::Byte(file) => {
                self.start_retained_byte(file, number, args, memory, pid, target)
            }
            PreparedAction::Layout { work, output } => {
                let pending = FilePending::new(Arc::default(), output, work.target().cloned());
                let signal = IoSignal::new(pid, target.clone());
                let subscriptions = vec![pending.result.subscribe(&signal)];
                self.queue_layout(work, pending, number, args, signal, subscriptions, target)
            }
            PreparedAction::Reply { reply, output } => {
                if let Some(open) = self.fifo_reply(number, &reply) {
                    return Some(self.start_fifo_open(open, number, args, pid, target));
                }
                self.complete_file_attempt(reply, output, number, args, memory, pid, target)
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
    pub(super) fn submit_file_work(
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
        if work.waiting() {
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
        if crate::file_advice::entry(number) {
            return Some(self.complete(
                number,
                args,
                crate::file_advice::call(
                    number,
                    args,
                    vfs.cache_fd_type(args[0] as u32, number == 213),
                ),
            ));
        }
        if number == 227 {
            return self.start_memory_sync(args, memory, pid, target);
        }
        if number == 25 && matches!(args[1], 1033 | 1034) {
            let control = match vfs.descriptor_control(args[0] as u32) {
                Ok(control) => control,
                Err(error) => return Some(IoAttempt::Complete(Err(error))),
            };
            if control.flags() & trames_vfs::O_PATH != 0 {
                return Some(IoAttempt::Complete(Err(Errno(9))));
            }
            let command =
                trames_vfs::FileCommand::Seals((args[1] == 1033).then_some(args[2] as u32));
            let work = trames_vfs::FileWork::from_vfs(vfs, control.filesystem_target(), command);
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
        if namespace::supported(number) {
            let (call, output) = match namespace::import(
                number,
                args,
                memory,
                || vfs.check_mount_admin(),
                |fd| vfs.capture_mount_idmap(fd),
            ) {
                Ok(call) => call,
                Err(error) => return Some(IoAttempt::Complete(Err(error))),
            };
            if !vfs.namespace_host_work() {
                // All instruction views are joined here. Use the original
                // caller VFS directly, as before worker admission existed.
                let reply = trames_vfs::FileReply::capture(|| call.execute(vfs));
                return Some(
                    self.complete_file_attempt(reply, output, number, args, memory, pid, target),
                );
            }
            let work = vfs.path_queries().namespace_work(call);
            if let Some(value) = self.prepare_filesystem_work(number, args, work, output, memory) {
                return Some(IoAttempt::Complete(value));
            }
            return self.start_prepared_file(number, args, memory, pid, target);
        }
        if number == 45 {
            if args[1] > i64::MAX as u64 {
                return Some(IoAttempt::Complete(Err(Errno(22))));
            }
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
                Some(Ok(fd)) => {
                    if let Some(open) = paths.pending_fifo_open(fd) {
                        return Some(self.start_fifo_open(open, number, args, pid, target));
                    }
                    return Some(IoAttempt::Complete(Ok(u64::from(fd))));
                }
                Some(Err(error)) => return Some(IoAttempt::Complete(Err(error))),
                None => {
                    let work = paths.take_open_work()?;
                    return match self.prepare_open_work(number, args, work, memory) {
                        Some(result) => Some(IoAttempt::Complete(result)),
                        None => self.start_prepared_file(number, args, memory, pid, target),
                    };
                }
            }
        }
        if number == 77 {
            if let Some(result) = trames_vfs::StreamTransfer::tee_empty(args[2], args[3] as u32) {
                return Some(self.complete(number, args, result));
            }
        }
        let (file, command, output) = if matches!(number, 71 | 76..=77 | 285) {
            let (file, command, output) = match copy_import(
                &vfs.shared_files(),
                || vfs.path_queries(),
                number,
                args,
                memory,
            )? {
                Ok(prepared) => prepared,
                Err(error) => return Some(IoAttempt::Complete(Err(error))),
            };
            let command = match command {
                Ok(command) => command,
                Err(error) => return Some(IoAttempt::Complete(Err(error))),
            };
            (file, command, output)
        } else {
            if !matches!(number, 46 | 47 | 62..=70 | 80 | 82..=84 | 267 | 286 | 287) {
                return None;
            }
            if matches!(number, 286 | 287) {
                if let Err(error) = crate::file_calls::vector_flags(args[5]) {
                    return Some(IoAttempt::Complete(Err(error)));
                }
            }
            let original = match vfs.shared_files().lookup(args[0] as u32)? {
                Ok(file) => file,
                Err(error) => return Some(IoAttempt::Complete(Err(fd_error(number, args, error)))),
            };
            if matches!(number, 63..=70 | 286 | 287) {
                if let Some(file_target) = original.nonbyte_target() {
                    let (imported, pending) = self.import_file_input(
                        || vfs.path_queries(),
                        &file_target,
                        number,
                        args,
                        memory,
                        false,
                        false,
                    );
                    if let Some((input, fault)) = pending {
                        return Some(self.park_file_input(input, fault, number, args, pid, target));
                    }
                    let (command, output) = match imported {
                        Ok(call) => call,
                        Err(error) => return Some(IoAttempt::Complete(Err(error))),
                    };
                    return Some(self.complete_file_attempt(
                        trames_vfs::FileWork::descriptor_owned(vfs, file_target, command),
                        output,
                        number,
                        args,
                        memory,
                        pid,
                        target,
                    ));
                }
            }
            let file = if matches!(number, 286 | 287)
                && args[3] == u64::MAX
                && original.file_target().is_none()
                && original.nonbyte_target().is_none()
            {
                let file = match self.retain_byte_file(number, args, original)? {
                    Ok(file) => file,
                    Err(error) => return Some(IoAttempt::Complete(Err(error))),
                };
                return self.start_owned_byte(Some(file), number, args, memory, pid, target);
            } else if matches!(number, 63..=66) {
                original
                    .file_target()
                    .or_else(|| original.nonbyte_target())?
            } else {
                original.filesystem_target()
            };
            if let Some(result) = self.read_zero_file(&file, number, args, memory) {
                return Some(IoAttempt::Complete(result));
            }
            let (imported, pending) = self.import_file_input(
                || vfs.path_queries(),
                &file,
                number,
                args,
                memory,
                file.regular_file(),
                file.unsigned_offsets(),
            );
            if let Some((input, fault)) = pending {
                return Some(self.park_file_input(input, fault, number, args, pid, target));
            }
            let (command, output) = match imported {
                Ok(call) => call,
                Err(error) => return Some(IoAttempt::Complete(Err(error))),
            };
            (file, command, output)
        };
        if let Some(result) = file.proc_io_local(&command, memory) {
            return Some(self.complete_file_attempt(
                trames_vfs::FileReply {
                    resources: trames_vfs::FileResources::file(&file),
                    result,
                    file_size_signal: false,
                    scratch: None,
                },
                output,
                number,
                args,
                memory,
                pid,
                target,
            ));
        }
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
                    self.complete_file_attempt(reply, output, number, args, memory, pid, target)
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
        if pending.result.cancelled() {
            return IoAttempt::Complete(Err(Errno(4)));
        }
        if let Some(input) = &pending.input {
            let Some(input) = input.lock().unwrap().take() else {
                return IoAttempt::Complete(Err(Errno(4)));
            };
            let input = match input {
                super::file_input::Accepted::File(input) => input,
                super::file_input::Accepted::Path(input) => {
                    return self.resume_path_input(input, number, args, memory, signal.pid, target)
                }
                super::file_input::Accepted::Byte(file) => {
                    return self.start_retained_byte(file, number, args, memory, signal.pid, target)
                }
                super::file_input::Accepted::Socket(call) => {
                    return self.start_retained_socket(call, memory, signal.pid, target)
                }
                super::file_input::Accepted::EventWait(call) => {
                    return self.start_retained_poll(call, args, memory, signal.pid, target, None)
                }
                super::file_input::Accepted::WaitInput(call) => {
                    return call.resume(self, memory, signal.pid, target)
                }
                super::file_input::Accepted::EpollControl(bytes) => {
                    return self.resume_epoll_control(bytes, args, memory, signal.pid, target)
                }
                super::file_input::Accepted::EpollControlWait(call) => {
                    return self.start_retained_epoll_control(call, args, signal.pid, target)
                }
                super::file_input::Accepted::Registration(call) => {
                    return call.resume(self, memory, signal.pid, target)
                }
                super::file_input::Accepted::UringEnter(call) => {
                    return call.resume(self, memory, signal.pid, target)
                }
                super::file_input::Accepted::AioLookup(call) => {
                    return call.resume(self, memory, signal.pid, target)
                }
                super::file_input::Accepted::AioSetup(call) => {
                    return call.resume(self, memory, signal.pid, target)
                }
                super::file_input::Accepted::Uts(call) => {
                    return call.resume(self, memory, signal.pid, target)
                }
                super::file_input::Accepted::TimerFd(call) => {
                    return call.resume(self, memory, signal.pid, target)
                }
                super::file_input::Accepted::Ioctl(call) => {
                    return call.resume(self, memory, signal.pid, target)
                }
                super::file_input::Accepted::UringSetup(mut call) => {
                    return match call.progress(memory) {
                        Ok(result) => {
                            self.urings.record_completed();
                            IoAttempt::Complete(result)
                        }
                        Err(fault) => self.park_input(
                            super::file_input::Accepted::UringSetup(call),
                            fault,
                            number,
                            args,
                            signal.pid,
                            target,
                        ),
                    }
                }
                super::file_input::Accepted::Pair(mut pair) => {
                    return match pair.progress(memory) {
                        Ok(result) => IoAttempt::Complete(result),
                        Err(fault) => self.park_input(
                            super::file_input::Accepted::Pair(pair),
                            fault,
                            number,
                            args,
                            signal.pid,
                            target,
                        ),
                    }
                }
            };
            let (result, fault) = input.read(number, args, memory, &mut self.scratch.borrow_mut());
            if let Some(fault) = fault {
                return self.park_file_input(input, fault, number, args, signal.pid, target);
            }
            return match result {
                Ok((command, output)) => {
                    let work = trames_vfs::FileWork::new(&input.paths, input.file, command);
                    self.submit_file_work(work, output, number, args, memory, signal.pid, target)
                }
                Err(error) => self.complete(number, args, Err(error)),
            };
        }
        if let Some(copy) = &pending.copyout {
            let (value, signal_owner) = {
                let mut slot = copy.lock().unwrap();
                let Some(copy) = slot.as_mut() else {
                    // This receipt already completed or was cancelled. It is
                    // not another syscall and cannot account a replacement FD.
                    return IoAttempt::Complete(Err(Errno(4)));
                };
                let value = copy.progress(memory);
                let signal_owner = copy.signal_owner;
                if value.is_ok() {
                    // Completion consumes the original receipt. Cloned stale
                    // handles cannot publish the result or its effects twice.
                    slot.take();
                }
                (value, signal_owner)
            };
            return match value {
                Ok(value) => Self::copyout_value(signal_owner, value),
                Err(fault) => Self::park_copyout(pending, fault, number, args, signal, target),
            };
        }
        let waiting = pending
            .waiting
            .as_ref()
            .and_then(|w| w.lock().unwrap().take());
        if let Some(work) = waiting {
            if !work.ready() {
                return self.park_file(pending, work, number, args, signal, memory, target);
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
                self.park_file(pending, work, number, args, signal, memory, target)
            }
            Some(trames_vfs::FileOutcome::Complete(reply)) => {
                if let Some(open) = self.fifo_reply(number, &reply) {
                    return self.start_fifo_open(open, number, args, signal.pid, target);
                }
                self.complete_file_attempt(
                    reply,
                    pending.output,
                    number,
                    args,
                    memory,
                    signal.pid,
                    target,
                )
            }
            Some(trames_vfs::FileOutcome::Owner(work)) => {
                IoAttempt::FileCheckpoint(FileCheckpoint::new(FileBoundary::Owner {
                    work,
                    output: pending.output,
                }))
            }
            Some(trames_vfs::FileOutcome::Layout(work)) => {
                self.queue_layout(work, pending, number, args, signal, subscriptions, target)
            }
            None => Self::wait_file(pending, number, args, signal, subscriptions, target),
        }
    }
    fn park_file_input(
        &self,
        input: super::file_input::Input,
        fault: trames_memory::PageFault,
        number: u32,
        args: [u64; 6],
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        self.park_input(
            super::file_input::Accepted::File(input),
            fault,
            number,
            args,
            pid,
            target,
        )
    }
    pub(super) fn park_byte_page(
        &self,
        file: RetainedByte,
        fault: trames_memory::PageFault,
        number: u32,
        args: [u64; 6],
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        self.park_input(
            super::file_input::Accepted::Byte(file),
            fault,
            number,
            args,
            pid,
            target,
        )
    }
    pub(super) fn park_socket_page(
        &self,
        call: RetainedSocket,
        fault: trames_memory::PageFault,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let number = call.number;
        let args = call.args;
        self.park_input(
            super::file_input::Accepted::Socket(call),
            fault,
            number,
            args,
            pid,
            target,
        )
    }
    pub(super) fn park_event_page(
        &self,
        call: Arc<crate::RetainedWait>,
        fault: trames_memory::PageFault,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let (number, args) = (call.number, call.args);
        let attempt = self.park_input(
            super::file_input::Accepted::EventWait(call.clone()),
            fault,
            number,
            args,
            pid,
            target,
        );
        let IoAttempt::Blocked(mut pending) = attempt else {
            unreachable!("accepted event output page")
        };
        pending.retained_poll = Some(call);
        IoAttempt::Blocked(pending)
    }
    pub(super) fn park_event_resource(
        &self,
        call: Arc<crate::RetainedWait>,
        blocked: trames_vfs::EpollBlocked,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let signal = IoSignal::new(pid, target.clone());
        let subscriptions = vec![blocked.subscribe(&signal)];
        let (number, args) = (call.number, call.args);
        let attempt = self.park_resource_input(
            super::file_input::Accepted::EventWait(call.clone()),
            number,
            args,
            signal,
            subscriptions,
            target,
        );
        let IoAttempt::Blocked(mut pending) = attempt else {
            unreachable!("original epoll admission wait")
        };
        pending.retained_poll = Some(call);
        IoAttempt::Blocked(pending)
    }
    /// A caught signal may finish a partial receive's msg_len/timeout copies.
    /// Preserve that original completion if its final user output faults.
    /// Caught-signal callers retain their delivery separately; this envelope
    /// also supports the legacy ordinary poll-output suspension path.
    #[allow(clippy::too_many_arguments)]
    pub fn interrupted_page(
        &self,
        byte: Option<&RetainedByte>,
        socket: Option<&RetainedSocket>,
        poll: Option<&Arc<crate::RetainedWait>>,
        number: u32,
        args: [u64; 6],
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<PendingIo> {
        let attempt = if let Some((file, fault)) =
            byte.and_then(|file| Some((file, file.take_input_fault()?)))
        {
            self.park_byte_page(file.clone(), fault, number, args, pid, target)
        } else if let Some((call, fault)) = socket.and_then(|call| Some((call, call.take_fault()?)))
        {
            self.park_socket_page(call.clone(), fault, pid, target)
        } else if let Some((call, fault)) = poll.and_then(|call| Some((call, call.take_fault()?))) {
            self.park_event_page(call.clone(), fault, pid, target)
        } else if let Some((call, blocked)) = poll.and_then(|call| Some((call, call.blocker()?))) {
            self.park_event_resource(call.clone(), blocked, pid, target)
        } else {
            return None;
        };
        let IoAttempt::Blocked(wait) = attempt else {
            unreachable!("original page continuation")
        };
        Some(wait)
    }
    /// The caller retains its selected signal and the original completion
    /// while this accepted output waits for a page. No I/O request is retried.
    pub fn interrupted_copy_fault(
        byte: Option<&RetainedByte>,
        socket: Option<&RetainedSocket>,
        poll: Option<&Arc<crate::RetainedWait>>,
    ) -> Option<trames_memory::PageFault> {
        byte.and_then(RetainedByte::take_input_fault)
            .or_else(|| socket.and_then(RetainedSocket::take_fault))
            .or_else(|| poll.and_then(|poll| poll.take_fault()))
    }
    pub(super) fn prepare_retained_byte(&self, number: u32, args: [u64; 6], file: RetainedByte) {
        self.file_prepared.replace(Some(PreparedFileCall {
            number,
            args,
            action: PreparedAction::Byte(file),
        }));
    }
    pub(super) fn invoke_pair_creation(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        let address = if number == 59 { args[0] } else { args[3] };
        if memory.check(address, 8, Access::Write).is_err() {
            return Some(Err(Errno(14)));
        }
        let factory = self.resources.as_ref()?;
        let pair = if number == 59 {
            factory.prepare_pipe(args[1] as u32)
        } else {
            factory.prepare_local_pair(args[0] as u32, args[1] as u32, args[2] as u32)
        };
        let mut pair = match pair {
            Ok(pair) => super::file_input::Pair::new(pair, address),
            Err(error) => return Some(Err(error)),
        };
        match pair.progress(memory) {
            Ok(result) => Some(result),
            Err(fault) => {
                self.file_prepared.replace(Some(PreparedFileCall {
                    number,
                    args,
                    action: PreparedAction::Input(
                        Box::new(super::file_input::Accepted::Pair(pair)),
                        fault,
                    ),
                }));
                None
            }
        }
    }
    pub(super) fn invoke_uring_setup(
        &self,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        let mut call = Box::new(super::uring::Setup::new(
            self.paths.as_ref()?.retain_context(),
            args,
        ));
        match call.progress(memory) {
            Ok(result) => {
                self.urings.record_completed();
                Some(result)
            }
            Err(fault) => {
                self.file_prepared.replace(Some(PreparedFileCall {
                    number: 425,
                    args,
                    action: PreparedAction::Input(
                        Box::new(super::file_input::Accepted::UringSetup(call)),
                        fault,
                    ),
                }));
                None
            }
        }
    }
    pub(super) fn park_input(
        &self,
        input: super::file_input::Accepted,
        fault: trames_memory::PageFault,
        number: u32,
        args: [u64; 6],
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let mut pending = FilePending::new(Arc::default(), FileOutput::None, input.file());
        pending.input = Some(Arc::new(Mutex::new(Some(input))));
        let signal = IoSignal::new(pid, target.clone());
        Self::park_copyout(pending, fault, number, args, signal, target)
    }
    pub(super) fn prepare_input(
        &self,
        input: super::file_input::Accepted,
        fault: trames_memory::PageFault,
        number: u32,
        args: [u64; 6],
    ) {
        self.file_prepared.replace(Some(PreparedFileCall {
            number,
            args,
            action: PreparedAction::Input(Box::new(input), fault),
        }));
    }
    pub(super) fn prepare_checkpoint(&self, call: FileCheckpoint, number: u32, args: [u64; 6]) {
        self.file_prepared.replace(Some(PreparedFileCall {
            number,
            args,
            action: PreparedAction::Checkpoint(call),
        }));
    }
    pub(super) fn prepare_epoll_control_call(
        &self,
        call: Box<trames_vfs::EpollControl>,
        args: [u64; 6],
    ) {
        self.file_prepared.replace(Some(PreparedFileCall {
            number: 21,
            args,
            action: PreparedAction::EpollControl(call),
        }));
    }
    pub(super) fn park_resource_input(
        &self,
        input: super::file_input::Accepted,
        number: u32,
        args: [u64; 6],
        signal: Arc<IoSignal>,
        subscriptions: Vec<IoSubscription>,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let mut pending = FilePending::new(Arc::default(), FileOutput::None, input.file());
        pending.input = Some(Arc::new(Mutex::new(Some(input))));
        Self::wait_file(pending, number, args, signal, subscriptions, target)
    }
    pub(super) fn invoke_path_input(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        let input = super::file_input::PathInput::new(
            self.paths.as_ref()?.retain_context(),
            self.files.clone(),
        );
        match input.read(number, args, memory) {
            super::file_input::Step::Pending(fault) => {
                self.file_prepared.replace(Some(PreparedFileCall {
                    number,
                    args,
                    action: PreparedAction::Input(
                        Box::new(super::file_input::Accepted::Path(input)),
                        fault,
                    ),
                }));
                None
            }
            super::file_input::Step::Reply(reply, output) => {
                self.finish_file_reply(number, args, reply, output, memory)
            }
            super::file_input::Step::Work(work, output) => {
                self.prepare_filesystem_work(number, args, work, output, memory)
            }
            super::file_input::Step::Fifo(open) => {
                self.prepare_fifo_open(number, args, open);
                None
            }
        }
    }
    fn resume_path_input(
        &self,
        input: super::file_input::PathInput,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        match input.read(number, args, memory) {
            super::file_input::Step::Pending(fault) => self.park_input(
                super::file_input::Accepted::Path(input),
                fault,
                number,
                args,
                pid,
                target,
            ),
            super::file_input::Step::Reply(reply, output) => {
                self.complete_file_attempt(reply, output, number, args, memory, pid, target)
            }
            super::file_input::Step::Work(work, output) => {
                self.submit_file_work(work, output, number, args, memory, pid, target)
            }
            super::file_input::Step::Fifo(open) => {
                self.start_fifo_open(open, number, args, pid, target)
            }
        }
    }
    #[allow(clippy::too_many_arguments)] // Accepted file and original result/wake context.
    fn queue_layout(
        &self,
        work: trames_vfs::FileWork,
        pending: FilePending,
        number: u32,
        args: [u64; 6],
        signal: Arc<IoSignal>,
        subscriptions: Vec<IoSubscription>,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        signal.reset();
        let fallback = match &self.file_layouts {
            Some(layouts) => layouts.submit(work, pending.result.clone()),
            None => Err(work),
        };
        match fallback {
            Ok(()) => Self::wait_file(pending, number, args, signal, subscriptions, target),
            Err(work) => IoAttempt::FileCheckpoint(FileCheckpoint::new(FileBoundary::Layout {
                work,
                output: pending.output,
            })),
        }
    }
    fn wait_file(
        pending: FilePending,
        number: u32,
        args: [u64; 6],
        signal: Arc<IoSignal>,
        subscriptions: Vec<IoSubscription>,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        IoAttempt::Blocked(PendingIo {
            process_vm: None,
            binder: None,
            aio: None,
            message: None,
            number,
            args,
            deadline: None,
            signal,
            flock: None,
            record: None,
            retained_byte: None,
            retained_socket: None,
            native_tcp: None,
            resource_deadline: None,
            retained_poll: None,
            epoll_revision: None,
            terminal_job: false,
            _subscriptions: subscriptions,
            host_subscription: None,
            socket_subscriptions: Vec::new(),
            uring: None,
            poll_uring: None,
            file: Some(pending),
            fifo_open: None,
            target: target.clone(),
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn park_file(
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
        let wait = match work.wait_sources(&signal) {
            Ok(wait) => wait,
            Err(error) => return IoAttempt::HostError(error),
        };
        let mut subscriptions = vec![pending.result.subscribe(&signal)];
        subscriptions.extend(wait.subscriptions);
        let mut native = Vec::new();
        if let Some(events) = match signal.host_events() {
            Ok(events) => events,
            Err(error) => return IoAttempt::HostError(error),
        } {
            for (fd, write) in wait.native {
                match events.subscribe(fd, write, &signal) {
                    Ok(s) => native.push(s),
                    Err(error) => return IoAttempt::HostError(error),
                }
            }
        }
        if work.ready() {
            signal.notify();
        }
        pending.result.begin();
        *pending
            .waiting
            .get_or_insert_with(Arc::default)
            .lock()
            .unwrap() = Some(work);
        IoAttempt::Blocked(PendingIo {
            process_vm: None,
            binder: None,
            aio: None,
            message: None,
            number,
            args,
            deadline: None,
            signal,
            flock: None,
            record: None,
            retained_byte: None,
            retained_socket: None,
            native_tcp: None,
            resource_deadline: wait.deadline,
            retained_poll: None,
            epoll_revision: None,
            terminal_job: false,
            _subscriptions: subscriptions,
            host_subscription: None,
            socket_subscriptions: native,
            uring: None,
            poll_uring: None,
            file: Some(pending),
            fifo_open: None,
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
    regular: bool,
    unsigned_offsets: bool,
) -> Result<(trames_vfs::FileCommand, FileOutput), Errno> {
    use trames_vfs::FileCommand as Command;
    let regular = regular && !unsigned_offsets;
    let offset = (matches!(number, 67..=70) || matches!(number, 286 | 287) && a[3] != u64::MAX)
        .then_some(a[3]);
    if matches!(number, 286 | 287) {
        crate::file_calls::vector_flags(a[5])?;
    }
    let regular_vectors = |write| {
        if offset.is_some_and(|off| off > i64::MAX as u64) && !unsigned_offsets {
            return Err(Errno(22));
        }
        Linux::file_vector_import::<true>(memory, a, write)
    };
    match number {
        62 => Ok((
            Command::Seek {
                offset: a[1] as i64,
                whence: a[2] as u32,
            },
            FileOutput::None,
        )),
        63 | 67 => {
            let count = Linux::file_scalar_count(memory, a, Access::Write, regular)?;
            Ok((Command::Read { count, offset }, FileOutput::Scalar(a[1])))
        }
        65 | 69 | 286 => {
            let (parts, count) = if regular {
                let vectors = regular_vectors(false)?;
                (vectors.parts, vectors.total)
            } else if unsigned_offsets || number == 65 || number == 286 && offset.is_none() {
                Linux::readv_parts(memory, a)?
            } else {
                Linux::positioned_vector_parts(memory, a, false)?
            };
            Ok((Command::Read { count, offset }, FileOutput::Vectors(parts)))
        }
        64 | 68 => {
            let count = Linux::file_scalar_count(memory, a, Access::Read, regular)?;
            scratch.resize(count, 0);
            memory.read(a[1], scratch).map_err(|_| Errno(14))?;
            Ok((
                Command::Write {
                    bytes: std::mem::take(scratch),
                    offset,
                },
                FileOutput::Write,
            ))
        }
        66 | 70 | 287 => {
            if regular {
                let vectors = regular_vectors(true)?;
                Linux::gather_parts(memory, &vectors.parts, vectors.total, scratch)?;
            } else if unsigned_offsets || number == 66 || number == 287 && offset.is_none() {
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
                FileOutput::Write,
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
        84 => Ok((
            Command::SyncRange {
                offset: a[1],
                length: a[2],
                flags: a[3] as u32,
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
        if crate::file_advice::entry(number) {
            let kind = self
                .paths
                .as_ref()?
                .cache_fd_type(a[0] as u32, number == 213);
            self.completed.set(self.completed.get() + 1);
            self.file_completed.set(self.file_completed.get() + 1);
            return Some(crate::file_advice::call(number, a, kind));
        }
        if number == 25 && matches!(a[1], 1033 | 1034) {
            if self.file_prepared(number, a) {
                return None;
            }
            let control = match self.resources.as_ref()?.descriptor_control(a[0] as u32) {
                Ok(control) => control,
                Err(error) => return Some(Err(error)),
            };
            if control.flags() & trames_vfs::O_PATH != 0 {
                return Some(Err(Errno(9)));
            }
            return self.prepare_file_fallback(
                number,
                a,
                control.filesystem_target(),
                trames_vfs::FileCommand::Seals((a[1] == 1033).then_some(a[2] as u32)),
                FileOutput::None,
                memory,
            );
        }
        if number == 77 {
            if let Some(result) = trames_vfs::StreamTransfer::tee_empty(a[2], a[3] as u32) {
                return Some(result);
            }
        }
        if matches!(number, 71 | 76..=77 | 285) {
            if self.file_prepared(number, a) {
                return None;
            }
            self.paths.as_ref()?;
            let (file, command, output) = match copy_import(
                self.membership.as_ref()?,
                || self.paths.as_ref().expect("source copy path authority"),
                number,
                a,
                memory,
            )? {
                Ok(prepared) => prepared,
                Err(error) => return Some(Err(error)),
            };
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
        if !matches!(number, 46 | 47 | 62..=70 | 80 | 82..=84 | 267 | 286 | 287) {
            return None;
        }
        if self.file_prepared(number, a) {
            return None;
        }
        if matches!(number, 286 | 287) {
            if let Err(error) = crate::file_calls::vector_flags(a[5]) {
                return Some(Err(error));
            }
        }
        let access = if let Some(files) = &self.membership {
            let original = match files.lookup(a[0] as u32)? {
                Ok(file) => file,
                Err(error) => return Some(Err(fd_error(number, a, error))),
            };
            if matches!(number, 82..=84 | 267) {
                trames_vfs::FileAccess::Full(original.filesystem_target())
            } else {
                match self.files.accept_or_return(original) {
                    Ok(fast) => trames_vfs::FileAccess::Fast(fast),
                    Err(original) => {
                        let descriptor = matches!(number, 63..=70 | 286 | 287)
                            .then(|| original.nonbyte_target())
                            .flatten();
                        if let Some(target) = descriptor {
                            trames_vfs::FileAccess::Descriptor(target)
                        } else {
                            if matches!(number, 286 | 287)
                                && a[3] == u64::MAX
                                && original.file_target().is_none()
                            {
                                let action = if let Some(byte) =
                                    self.retain_byte_file(number, a, original.clone())
                                {
                                    match byte {
                                        Ok(file) => PreparedAction::Byte(file),
                                        Err(error) => return Some(Err(error)),
                                    }
                                } else {
                                    match self.prepare_v2_ip(original, number, a, memory)? {
                                        Ok(call) => PreparedAction::Socket(call),
                                        Err(error) => return Some(Err(error)),
                                    }
                                };
                                self.file_prepared.replace(Some(PreparedFileCall {
                                    number,
                                    args: a,
                                    action,
                                }));
                                return None;
                            }
                            let target = if matches!(number, 63..=66) {
                                original
                                    .file_target()
                                    .or_else(|| original.nonbyte_target())?
                            } else {
                                original.filesystem_target()
                            };
                            trames_vfs::FileAccess::Full(target)
                        }
                    }
                }
            }
        } else {
            self.files.resolve(a[0] as u32)?
        };
        let (fast, target) = match access {
            trames_vfs::FileAccess::Fast(file) => {
                let target = file.target();
                (Some(file), target)
            }
            trames_vfs::FileAccess::Full(target) => {
                if let Some(result) = self.read_zero_file(&target, number, a, memory) {
                    return Some(result);
                }
                (None, Some(target))
            }
            trames_vfs::FileAccess::Descriptor(target) => {
                let (imported, pending) = self.import_file_input(
                    || self.paths.as_ref().unwrap().retain_context(),
                    &target,
                    number,
                    a,
                    memory,
                    false,
                    false,
                );
                if let Some((input, fault)) = pending {
                    self.file_prepared.replace(Some(PreparedFileCall {
                        number,
                        args: a,
                        action: PreparedAction::Input(
                            Box::new(super::file_input::Accepted::File(input)),
                            fault,
                        ),
                    }));
                    return None;
                }
                let (command, output) = match imported {
                    Ok(prepared) => prepared,
                    Err(error) => return Some(Err(error)),
                };
                let reply =
                    trames_vfs::FileWork::descriptor_reply(self.paths.as_ref()?, target, command);
                return self.finish_file_reply(number, a, reply, output, memory);
            }
        };
        let regular = fast.is_some() || target.as_ref().is_some_and(|file| file.regular_file());
        let unsigned = target.as_ref().is_some_and(|file| file.unsigned_offsets());
        let (imported, pending) = if let Some(target) = &target {
            self.import_file_input(
                || self.paths.as_ref().unwrap().retain_context(),
                target,
                number,
                a,
                memory,
                regular,
                unsigned,
            )
        } else {
            (
                import(
                    number,
                    a,
                    memory,
                    &mut self.scratch.borrow_mut(),
                    regular,
                    unsigned,
                ),
                None,
            )
        };
        if let Some((input, fault)) = pending {
            self.file_prepared.replace(Some(PreparedFileCall {
                number,
                args: a,
                action: PreparedAction::Input(
                    Box::new(super::file_input::Accepted::File(input)),
                    fault,
                ),
            }));
            return None;
        }
        let (mut command, output) = match imported {
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
                Command::Read { count, offset } => {
                    file.read_reply(*count, *offset, &mut self.disk_cache.borrow_mut())
                }
                Command::Write { bytes, offset } => file
                    .write(bytes, *offset, &mut self.disk_cache.borrow_mut())
                    .map(|r| r.map(|n| Value::Count(n as u64))),
                Command::Seek { offset, whence } => {
                    file.seek(*offset, *whence).map(|r| r.map(Value::Count))
                }
                Command::Stat => Some(file.stat().map(|stat| {
                    Value::Stat(self.resources.as_ref().map_or(stat, |factory| {
                        factory.local_credentials().user_namespace.stat(stat)
                    }))
                })),
                _ => None,
            }
        });
        if let Some(result) = result {
            let scratch = match &mut command {
                trames_vfs::FileCommand::Write { bytes, .. } => Some(std::mem::take(bytes)),
                _ => None,
            };
            return self.finish_file_reply(
                number,
                a,
                trames_vfs::FileReply {
                    resources: fast
                        .as_ref()
                        .map_or_else(Default::default, |file| file.output_resources(&result)),
                    result,
                    file_size_signal: false,
                    scratch,
                },
                output,
                memory,
            );
        }
        self.prepare_file_fallback(number, a, target?, command, output, memory)
    }
}

fn fd_error(number: u32, a: [u64; 6], error: Errno) -> Errno {
    if number == 47 {
        if let Err(range) = trames_vfs::Vfs::allocation_end(a[2], a[3]) {
            return range;
        }
    }
    error
}
type ImportedCopy = (
    trames_vfs::FileTarget,
    Result<trames_vfs::FileCommand, Errno>,
    FileOutput,
);

fn copy_import<Q: std::borrow::Borrow<trames_vfs::PathQueries>>(
    files: &trames_vfs::SharedFiles,
    paths: impl FnOnce() -> Q,
    number: u32,
    a: [u64; 6],
    memory: &impl CpuMemory,
) -> Option<Result<ImportedCopy, Errno>> {
    if number == 77 {
        let input = match files.lookup(a[0] as u32)? {
            Ok(fd) => fd,
            Err(e) => return Some(Err(e)),
        };
        let output = match files.lookup(a[1] as u32)? {
            Ok(fd) => fd,
            Err(e) => return Some(Err(e)),
        };
        let target = output.filesystem_target();
        let transfer = trames_vfs::StreamTransfer::tee(input, output, a[2], a[3] as u32)
            .map(|op| trames_vfs::FileCommand::Transfer(Arc::new(std::sync::Mutex::new(op))));
        return Some(Ok((
            target,
            transfer,
            FileOutput::CopyOffsets { from: 0, to: 0 },
        )));
    }
    let range = number == 285;
    let splice = number == 76;
    if range && a[5] != 0 || splice && a[5] & !15 != 0 {
        return Some(Err(Errno(22)));
    }
    let (input, output, from, to, count, flags) = if splice {
        (a[0], a[2], a[1], a[3], a[4], a[5] as u32)
    } else if range {
        (a[0], a[2], a[1], a[3], a[4], 0)
    } else {
        (a[1], a[0], a[2], 0, a[3], 0)
    };
    // Resolve each original OFD once. A concurrent close/reuse must not retarget
    // a pair already accepted while deciding between file and stream work.
    let input = files.lookup(input as u32);
    let output = files.lookup(output as u32);
    let (input, output) = match (input, output) {
        (Some(Ok(input)), Some(Ok(output))) => (input, output),
        (input, output) => {
            // No data operation can be reached: at least one role has an
            // actual lookup error or absent capability, frozen for this call.
            let paths = paths();
            let result: Result<u64, Errno> =
                paths.borrow().fd_pair([input, output], |vfs, aliases| {
                    let mut args = a;
                    if splice || range {
                        args[0] = aliases[0] as u64;
                        args[2] = aliases[1] as u64;
                    } else {
                        args[1] = aliases[0] as u64;
                        args[0] = aliases[1] as u64;
                    }
                    if splice {
                        let (from, to) = crate::file_calls::splice_parameters(vfs, args, memory)?;
                        vfs.check_splice(aliases[0], aliases[1], from, to)?;
                    } else {
                        crate::file_calls::CopyParameters::prepare(vfs, number, args, memory)?;
                    }
                    unreachable!("a frozen rejected operand cannot pass transfer admission")
                })?;
            return Some(Err(result.unwrap_err()));
        }
    };
    let offset = |pointer| -> Result<Option<u64>, Errno> {
        if pointer == 0 {
            return Ok(None);
        }
        Linux::check(memory, pointer, 8, Access::Read)?;
        Linux::check(memory, pointer, 8, Access::Write)?;
        let value = memory.read_u64(pointer).map_err(|_| Errno(14))?;
        if !range && value > i64::MAX as u64 {
            Err(Errno(22))
        } else {
            Ok(Some(value))
        }
    };
    if (splice || !range && (input.file_target().is_none() || output.file_target().is_none()))
        && trames_vfs::StreamTransfer::admitted(&input, &output)
    {
        let target = output.filesystem_target();
        let command = trames_vfs::FileCommand::Transfer(Arc::new(std::sync::Mutex::new(
            trames_vfs::StreamTransfer::new(
                input,
                output,
                offset(from),
                offset(to),
                count,
                splice,
                flags,
            ),
        )));
        return Some(Ok((
            target,
            Ok(command),
            FileOutput::CopyOffsets { from, to },
        )));
    }
    if splice || input.file_target().is_none() || output.file_target().is_none() {
        let paths = paths();
        let result =
            paths
                .borrow()
                .fd_pair([Some(Ok(input)), Some(Ok(output))], |vfs, aliases| {
                    let mut args = a;
                    if splice || range {
                        args[0] = aliases[0] as u64;
                        args[2] = aliases[1] as u64;
                    } else {
                        args[1] = aliases[0] as u64;
                        args[0] = aliases[1] as u64;
                    }
                    if splice {
                        let (from, to) = crate::file_calls::splice_parameters(vfs, args, memory)?;
                        vfs.check_splice(aliases[0], aliases[1], from, to)
                    } else {
                        crate::file_calls::CopyParameters::prepare(vfs, number, args, memory)
                            .map(|_| ())
                    }
                })?;
        // A valid but unadmitted body still lacks actual source capability.
        // A canonical prelude error is complete and requires no owner replay.
        return result.err().map(Err);
    }
    let input = input.file_target().expect("accepted regular input");
    let output = output.file_target().expect("accepted regular output");
    let command = if range && a[5] != 0 {
        Err(Errno(22))
    } else {
        Ok(trames_vfs::FileCommand::Copy {
            input,
            transfer: Arc::new(std::sync::Mutex::new(trames_vfs::FileCopy::new(
                offset(from),
                offset(to),
                count,
                range,
            ))),
        })
    };
    Some(Ok((output, command, FileOutput::CopyOffsets { from, to })))
}

#[cfg(test)]
#[path = "file_tests.rs"]
mod tests;
#[cfg(test)]
pub(super) use tests::{fuse_socket_error_step, mount_socket_fuse};
